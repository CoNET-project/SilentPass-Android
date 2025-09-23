package com.silentPass.vpn

import android.R
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import java.io.*
import java.net.*
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class SocketServerService : Service() {
    private val DEBUG_FORWARD = false
    // ====== Server State ======
    private var serverThread: Thread? = null
    @Volatile private var isRunning = true
    private var layerMinus: LayerMinus? = null
    private var serverSocket: ServerSocket? = null
    private val LOG_TAG = "SocketServerService"

    // ====== ThreadPool (avoid per-conn thread explosion) ======
    private val threadCounter = AtomicInteger(0)
    private val threadPoolExecutor = ThreadPoolExecutor(
        50, 200, 30L, TimeUnit.SECONDS,
        SynchronousQueue<Runnable>(),
        ThreadFactory { r ->
            Thread(r).apply {
                name = "ProxyWorker-${threadCounter.incrementAndGet()}"
                isDaemon = true
                priority = Thread.NORM_PRIORITY
            }
        },
        ThreadPoolExecutor.DiscardOldestPolicy() // 过载时丢弃最老任务，保护当前活跃连接
    ).apply {
        // 核心线程也允许在空闲 keepAlive 后回收：高峰过后自动收缩
        allowCoreThreadTimeOut(true)
        prestartAllCoreThreads() // 预热核心线程，降低冷启动抖动
    }

    // 自适应微等待 prime：每轮最多阻塞 stepMs（默认5ms），若没数据则再等一轮，最多 maxRounds 轮；合并到 maxBytes（默认16KiB）
    private fun capturePrimeAdaptive(
        cliIn: BufferedInputStream,
        client: Socket,
        stepMs: Int = 5,      // 第2轮开始的步长
        maxRounds: Int = 3,    // 总轮数
        maxBytes: Int = 16 * 1024
    ): ByteArray? {
        val buf = ByteArray(maxBytes)
        var total = 0
        val prev = client.soTimeout
        val TLS_Length = 500

        try {
            // 0ms：非阻塞检查
            val immediate = cliIn.available()
            if (immediate > 0) {
                total = cliIn.read(buf, 0, minOf(immediate, maxBytes))
                if (total >= TLS_Length) {
                    return buf.copyOf(total)
                }
            }

            // 渐进式等待
            for (round in 0 until maxRounds) {
                if (total >= maxBytes) break

                // 关键：第一轮10ms，后续5ms
                val currentStepMs = if (round == 0) 10 else stepMs
                client.soTimeout = currentStepMs

                try {
                    val n = cliIn.read(buf, total, maxBytes - total)
                    if (n > 0) {
                        total += n
                        // 贪婪读取（限制次数）
                        var attempts = 0
                        while (attempts < 3 && cliIn.available() > 0 && total < maxBytes) {
                            val extra = cliIn.read(buf, total,
                                minOf(cliIn.available(), maxBytes - total, 4096))
                            if (extra <= 0) break
                            total += extra
                            attempts++
                        }

                        if (total >= TLS_Length) break
                    }
                } catch (_: SocketTimeoutException) {
                    if (total > TLS_Length - 100) break  // 有部分数据就返回
                }
            }
        } finally {
            client.soTimeout = prev
            recordPrime(total)
        }

        return if (total > 0) buf.copyOf(total) else null
    }

    // 仅在给定预算内合并已到达的首包；超时立即返回；LM/DIRECT 共用
    private fun capturePrimeWithBudget(
        cliIn: BufferedInputStream,
        client: Socket,
        budgetMs: Int = 10,
        maxBytes: Int = 16 * 1024
    ): ByteArray? {
        var total = 0
        val buf = ByteArray(maxBytes)
        val prev = client.soTimeout
        try {
            client.soTimeout = budgetMs
            while (total < maxBytes) {
                val n = try { cliIn.read(buf, total, maxBytes - total) }
                catch (_: java.net.SocketTimeoutException) { break }
                if (n <= 0) break
                total += n
                if (cliIn.available() == 0) break
            }
        } catch (_: Exception) {
            // 忽略 prime 异常
        } finally {
            try { client.soTimeout = prev } catch (_: Exception) {}
            try { recordPrime(total) } catch (_: Exception) {}
        }
        return if (total > 0) buf.copyOf(total) else null
    }

    // ====== Event-style metrics (print only on connection OPEN/CLOSE) ======
    private val activeConns = AtomicInteger(0)
    private val connSeq = AtomicLong(0)
    private fun logPoolSnapshot(event: String, connId: Long, note: String = "") {
        val q = threadPoolExecutor.queue
        val a = primeAttempts.get()
        val h = primeHits.get()
        val rate = if (a > 0) (h * 100 / a) else 0
        val avgB = if (h > 0) (primeBytesSum.get() / h) else 0
        Log.i(
            LOG_TAG,
            "[$event] conn#$connId " +
                    "activeConns=${activeConns.get()} " +
                    "pool={active:${threadPoolExecutor.activeCount}, size:${threadPoolExecutor.poolSize}/${threadPoolExecutor.maximumPoolSize}, largest:${threadPoolExecutor.largestPoolSize}} " +
                    "tasks={submitted:${threadPoolExecutor.taskCount}, completed:${threadPoolExecutor.completedTaskCount}} " +
                    "queue.size=${q.size} prime={hit:$h/att:$a, rate:${rate}%, avgB:$avgB} $note"
        )
    }
    private fun onConnOpen(connId: Long)  { activeConns.incrementAndGet(); logPoolSnapshot("OPEN",  connId) }
    private fun onConnClose(connId: Long) { if (activeConns.decrementAndGet() < 0) activeConns.set(0); logPoolSnapshot("CLOSE", connId) }

    // ====== High-throughput forwarder (NIO Channels + Direct ByteBuffer) ======
    // - Natural backpressure: write blocks when socket send buffer is full
    // - Adaptive flush: small-flow (e.g., TLS ClientHello) flush eagerly; bulk-flow flush in batches
    private fun forwardTrafficAsync(
        input: InputStream,
        output: OutputStream,
        bufferSize: Int = 256 * 1024,
        onDone: (() -> Unit)? = null,
        onEof: (() -> Unit)? = null,
        minBytesBeforeEofCallback: Long = 0   // 新增：EOF 回调的最小搬运字节数
    ): Future<*> {
        return threadPoolExecutor.submit {
            if (DEBUG_FORWARD) Log.d(LOG_TAG, "Start forwarding from ${input.javaClass.simpleName} to ${output.javaClass.simpleName}")
            var src: java.nio.channels.ReadableByteChannel? = null
            var dst: java.nio.channels.WritableByteChannel? = null


            try {
                // 惰性启动 + 压力熔断：避免大量“空转转发器”占坑
                try {
                    var checks = 0
                    while (checks < 5 && input.available() == 0) {
                        checks++
                        // 队列&线程高压：放弃该方向（另一方向仍在运行，优先保活隧道）
                        if (threadPoolExecutor.queue.size > 180 && threadPoolExecutor.activeCount > 150) {
                            if (DEBUG_FORWARD) Log.d(LOG_TAG, "Skip starting idle forwarder under pressure")
                            return@submit
                        }
                        Thread.sleep(10)
                    }
                    if (DEBUG_FORWARD) Log.d(LOG_TAG, "input available bytes: ${input.available()}")
                } catch (_: Exception) {}

                src = Channels.newChannel(input)
                dst = Channels.newChannel(output)
                val buf = ByteBuffer.allocateDirect(bufferSize)
                var totalBytes = 0L             // 该方向由本任务实际搬运的字节数
                var sinceLastFlush = 0L
                val WARMUP_LIMIT = 128 * 1024     // small-flow threshold
                val FLUSH_THRESHOLD = 256 * 1024  // 大流阶段 256KiB 才批量 flush，减少系统调用

                while (true) {
                    val nRead = try {
                        src.read(buf)
                    } catch (_: SocketTimeoutException) {
                        // 上游短暂停笔：如果手里攒着数据就冲一下，避免尾部卡住
                        if (output is BufferedOutputStream) {
                            try { output.flush() } catch (_: Exception) {}
                        }
                        continue
                    } catch (_: java.nio.channels.ClosedByInterruptException) {
                        break
                    } catch (_: java.nio.channels.AsynchronousCloseException) {
                        break
                    }
                    if (nRead == -1) {
                        if (DEBUG_FORWARD) Log.d(LOG_TAG, "EOF reached after forwarding $totalBytes bytes")
                        try { (output as? BufferedOutputStream)?.flush() } catch (_: Exception) {}
                        // 只有在本任务确实搬过至少 minBytesBeforeEofCallback 才触发 onEof（半关闭）
                        if (totalBytes >= minBytesBeforeEofCallback) {
                            try { onEof?.invoke() } catch (_: Exception) {}
                        } else {
                            Log.d(LOG_TAG, "Skip half-close: forwarded=$totalBytes < $minBytesBeforeEofCallback")
                        }
                        break
                    }
                    if (nRead == 0) continue

                    totalBytes += nRead
                    buf.flip()
                    var wroteThisChunk = 0
                    while (buf.hasRemaining()) {
                        val nWritten = try { dst.write(buf) }
                        catch (_: java.nio.channels.ClosedChannelException) {
                            Log.d(LOG_TAG, "Output channel closed after $totalBytes bytes"); return@submit
                        }
                        if (nWritten == 0) Thread.yield()
                        wroteThisChunk += nWritten
                    }
                    buf.compact()

                    // Adaptive flush: protect TLS handshakes and tiny requests from buffering
                    if (output is BufferedOutputStream) {
                        sinceLastFlush += wroteThisChunk
                        val inWarmup = totalBytes <= WARMUP_LIMIT

                        // 1) 暖身（<=128KiB）：每块都刷，保护首包
                        // 2) 大流：累计达 256KiB 再刷，降低 flush 频率
                        if (inWarmup || sinceLastFlush >= FLUSH_THRESHOLD) {
                            try { output.flush() } catch (_: Exception) {}
                            sinceLastFlush = 0
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Error forwarding traffic (NIO)", e)
            } finally {
                // Half-close friendly: close read side; flush write side; let peer direction finish
                try { src?.close() } catch (_: Exception) {}
                try { (output as? BufferedOutputStream)?.flush() } catch (_: Exception) {}
                try { onDone?.invoke() } catch (_: Exception) {}
            }
        }
    }

    // ====== Android Service lifecycle ======
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(1, createNotification()) // must start within 5s
        Log.d(LOG_TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent?.getStringExtra("VPN_DATA_B64")?.let { b64 ->
            try {
                val data = Base64.decode(b64, Base64.DEFAULT)
                val json = String(data, Charsets.UTF_8)
                val startVPNData = Gson().fromJson(json, StartVPNData::class.java)
                this.layerMinus = LayerMinus(startVPNData)

            } catch (e: Exception) {
                Log.e(LOG_TAG, "Failed to parse VPN data", e)
            }
        }
        if (serverThread == null || !serverThread!!.isAlive) startSocketServer()
        return START_STICKY
    }

    private fun startSocketServer() {
        serverThread = Thread {
            try {
                serverSocket = ServerSocket(8888, 512)
                Log.d(LOG_TAG, "Server started on port 8888")
                while (isRunning) {
                    val client = serverSocket?.accept() ?: break
                    val connId = connSeq.incrementAndGet()
                    onConnOpen(connId)
                    threadPoolExecutor.execute { handleClient(client, connId) }
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Server error", e)
            } finally {
                try { serverSocket?.close() } catch (_: Exception) {}
            }
        }.apply { isDaemon = true }
        serverThread?.start()
    }

    override fun onDestroy() {
        isRunning = false
        try { serverSocket?.close() } catch (_: Exception) {}
        serverThread?.interrupt()
        super.onDestroy()
        Log.d(LOG_TAG, "onDestroy called")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ====== Helpers ======
    private fun readFirstChunkOrNull(ins: InputStream): ByteArray? {
        val buf = ByteArray(4096)
        val n = try { ins.read(buf) } catch (_: Exception) { return null }
        return when {
            n > 0  -> buf.copyOf(n)
            n == 0 -> ByteArray(0)
            else   -> null
        }
    }

    private fun setSocketPerfOptions(a: Socket?, b: Socket?) {
        try {
            a?.tcpNoDelay = true
            a?.sendBufferSize = 256 * 1024
            a?.receiveBufferSize = 256 * 1024
            a?.soTimeout = 500   // 500ms 读超时，用于触发 idle flush
            b?.tcpNoDelay = true
            b?.sendBufferSize = 256 * 1024
            b?.receiveBufferSize = 256 * 1024
            b?.soTimeout = 500
        } catch (_: Exception) {}
    }

    // ====== Client dispatcher ======
    private fun handleClient(client: Socket, connId: Long) {
        try {
            val input  = BufferedInputStream(client.getInputStream())
            val output = client.getOutputStream()
            input.mark(4096)
            val version = input.read()
            input.reset()

            when (version) {
                0x04 -> handleSocks4(client, input, output, connId)
                0x05 -> handleSocks5(client, input, output, connId)
                else -> {
                    val reader = BufferedReader(InputStreamReader(input))
                    val requestLine = reader.readLine()
                    Log.d(LOG_TAG, "HTTP/s forwarding $requestLine")
                    if (requestLine?.startsWith("CONNECT") == true) {
                        handleHttpsConnect(client, input, requestLine, connId)
                    } else {
                        handleHttpProxy(client, requestLine, reader, connId)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Error handling client", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }

    // ====== HTTP (non-CONNECT) ======
    private fun handleHttpProxy(client: Socket, requestLine: String?, reader: BufferedReader, connId: Long) {
        if (requestLine == null) {
            Log.e(LOG_TAG, "Null request line")
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId); return
        }

        try {
            val headers = mutableListOf<String>()
            var line: String?
            while (reader.readLine().also { line = it } != null && line!!.isNotEmpty()) {
                headers.add(line!!)
            }

            val parts = requestLine.split(" ")
            if (parts.size < 3) {
                Log.e(LOG_TAG, "Invalid request line")
                try { client.close() } catch (_: Exception) {}
                onConnClose(connId); return
            }
            val method = parts[0]
            val fullUrl = parts[1]
            val httpVersion = parts[2]

            val url = URL(fullUrl)
            val host = url.host
            val port = if (url.port != -1) url.port else 80
            val path = url.file.ifEmpty { "/" }

            // Body (if any)
            var body: CharArray? = null
            val contentLength = headers.find { it.startsWith("Content-Length", ignoreCase = true) }
                ?.split(":")?.getOrNull(1)?.trim()?.toIntOrNull() ?: 0
            if (contentLength > 0) {
                body = CharArray(contentLength)
                reader.read(body)
            }

            // Rewrite: full URL -> path (strip Proxy-* headers)
            val sb = StringBuilder()
            sb.append("$method $path $httpVersion\r\n")
            for (h in headers) if (!h.startsWith("Proxy-", ignoreCase = true)) sb.append(h).append("\r\n")
            sb.append("\r\n")
            if (body != null) sb.append(String(body))
            val requestBody = sb.toString() // == firstData for HTTP

            val upstream: Socket? = if (layerMinus != null) {
                // LayerMinus expects firstData packaged inside
                layerMinus?.connectToLayerMinus(host, port.toString(), requestBody.toByteArray(Charsets.UTF_8))
            } else {
                try { Socket(host, port) } catch (e: Exception) {
                    Log.e(LOG_TAG, "Failed to connect to $host:$port", e); null
                }
            }
            if (upstream == null) {
                try { client.close() } catch (_: Exception) {}
                onConnClose(connId); return
            }

            setSocketPerfOptions(client, upstream)
            // 仅 SOCKS4/4a：上游首包可能慢半拍，放宽读超时，减少首个响应被“早判超时”带来的抖动
            try { upstream.soTimeout = 300 } catch (_: Exception) {}
            // DIRECT must write firstData first, then start bidirectional pumps
            if (layerMinus == null) {
                BufferedWriter(OutputStreamWriter(upstream.getOutputStream())).apply {
                    write(requestBody); flush()
                }
            }

            val upIn  = BufferedInputStream(upstream.getInputStream(),   256 * 1024)
            val upOut = BufferedOutputStream(upstream.getOutputStream(), 256 * 1024)
            val cliIn  = BufferedInputStream(client.getInputStream(),    256 * 1024)
            val cliOut = BufferedOutputStream(client.getOutputStream(),  256 * 1024)

            val remaining = AtomicInteger(2)
            val onBothDone = {
                if (remaining.decrementAndGet() == 0) {
                    try { cliOut.flush() } catch (_: Exception) {}
                    try { upOut.flush() }  catch (_: Exception) {}
                    try { upstream.close() } catch (_: Exception) {}
                    try { client.close() }   catch (_: Exception) {}
                    onConnClose(connId)
                }
            }
            forwardTrafficAsync(upIn,  cliOut, onDone = onBothDone) // upstream -> client
            forwardTrafficAsync(
                cliIn, upOut,
                onDone = onBothDone,
                onEof  = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
                minBytesBeforeEofCallback = 1
            )
        } catch (e: Exception) {
            Log.e(LOG_TAG, "HTTP proxy error", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }

    // ====== HTTPS (CONNECT) ======
    private fun handleHttpsConnect(client: Socket, input: BufferedInputStream, requestLine: String, connId: Long) {
        try {
            val parts = requestLine.split(" ")
            val target = parts[1]
            val host = target.substringBefore(":")
            val port = target.substringAfter(":").toIntOrNull() ?: 443

            // Tell client the tunnel is ready
            BufferedWriter(OutputStreamWriter(client.getOutputStream())).apply {
                write("HTTP/1.1 200 Connection Established\r\n\r\n")
                flush()
            }

            // 统一：在分支前“微等待 prime”（≤10ms；复用同一个 BufferedInputStream）
            val cliIn = input
            val firstData = capturePrimeAdaptive(cliIn, client, stepMs = 5, maxRounds = 4, maxBytes = 16 * 1024)

            val upstream: Socket? = if (layerMinus != null) {
                layerMinus?.connectToLayerMinus(host, port.toString(), firstData)
            } else {
                try { Socket(host, port) } catch (_: Exception) { null }
            }


            if (upstream == null) {
                try { client.close() } catch (_: Exception) {}
                onConnClose(connId); return
            }
            setSocketPerfOptions(client, upstream)



            try { upstream.soTimeout = 300 } catch (_: Exception) {} // 仅 CONNECT 放宽

            val upIn   = BufferedInputStream(upstream.getInputStream(),   256 * 1024)
            val upOutB = BufferedOutputStream(upstream.getOutputStream(), 256 * 1024)
            val cliOut = BufferedOutputStream(client.getOutputStream(),   256 * 1024)
            // DIRECT：若抓到了首包，先踢给上游
            if (layerMinus == null && firstData != null && firstData.isNotEmpty()) {
                try { upOutB.write(firstData); upOutB.flush() } catch (_: Exception) {}
            }


            // 双泵复用同一个 cliIn；cli->up 方向保持 minBytesBeforeEofCallback=1
            val remaining = java.util.concurrent.atomic.AtomicInteger(2)
            val onBothDone = {
                if (remaining.decrementAndGet() == 0) {
                    try { cliOut.flush() } catch (_: Exception) {}
                    try { upOutB.flush() } catch (_: Exception) {}
                    try { upstream.close() } catch (_: Exception) {}
                    try { client.close() }   catch (_: Exception) {}
                    onConnClose(connId)
                }
            }
            forwardTrafficAsync(
                upIn, cliOut,
                onDone = onBothDone,
                onEof  = { try { client.shutdownOutput() } catch (_: Exception) {} }
            )
            forwardTrafficAsync(
                cliIn, upOutB,
                onDone = onBothDone,
                onEof  = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
                minBytesBeforeEofCallback = 1 // 防 0B EOF 误半关
            )

            Log.d(LOG_TAG, "Forwarding $host:$port via CONNECT")
        } catch (e: Exception) {
            Log.e(LOG_TAG, "HTTPS CONNECT failed", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }

    // ====== SOCKS4 ======
    // ====== SOCKS4 / SOCKS4a ======
    private fun handleSocks4(client: Socket, input: InputStream, output: OutputStream, connId: Long) {
        try {
            // VER(0x04)
            val ver = input.read()
            if (ver != 0x04) {
                // 非 SOCKS4：按失败 8 字节返回
                try { output.write(byteArrayOf(0x00, 0x5b, 0,0, 0,0,0,0)); output.flush() } catch (_: Exception) {}
                client.close(); onConnClose(connId); return
            }

            // CMD，仅支持 CONNECT(0x01)
            val cmd = input.read()
            if (cmd != 0x01) {
                try { output.write(byteArrayOf(0x00, 0x5b, 0,0, 0,0,0,0)); output.flush() } catch (_: Exception) {}
                client.close(); onConnClose(connId); return
            }

            // DSTPORT (network-order)
            val port = (input.read() shl 8) or input.read()
            // DSTIP
            val ip = ByteArray(4); input.read(ip)

            // USERID (NUL terminated)
            while (input.read() != 0) { /* discard */ }

            // SOCKS4a: ip=0.0.0.x 且 x!=0 时，后续还有域名（NUL 结尾）
            val isSocks4a = (ip[0].toInt() == 0 && ip[1].toInt() == 0 && ip[2].toInt() == 0 && ip[3].toInt() != 0)


            // 直接使用原始host（IP或域名），不做解析
            val destHost = if (isSocks4a) {
                // SOCKS4a：域名
                val sb = StringBuilder()
                var b: Int
                while (input.read().also { b = it } != 0 && b != -1) sb.append(b.toChar())
                sb.toString()
            } else {
                // SOCKS4：IP地址字符串
                ip.joinToString(".") { (it.toInt() and 0xFF).toString() }
            }

            // 立即发送granted响应（使用占位符地址）
            val granted = byteArrayOf(
                0x00, 0x5a,  // 成功
                0x00, 0x00,  // 端口占位
                0x00, 0x00, 0x00, 0x00  // IP占位
            )

            try {
                output.write(granted)
                output.flush()
            } catch (_: Exception) {}


            // 捕获首包
            val cliIn = if (input is BufferedInputStream) input else BufferedInputStream(input, 256 * 1024)
            val firstData = capturePrimeAdaptive(cliIn, client, stepMs = 5, maxRounds = 4)


            val upstream: Socket? = if (layerMinus != null) {
                layerMinus?.connectToLayerMinus(destHost, port.toString(), firstData)
            } else {
                try { Socket(destHost, port) } catch (_: Exception) { null }
            }


            if (upstream == null) {
                try { output.write(byteArrayOf(0x00, 0x5b, 0,0, 0,0,0,0)); output.flush() } catch (_: Exception) {}
                client.close(); onConnClose(connId); return
            }

            setSocketPerfOptions(client, upstream)

            // —— 0x5A 成功应答：回“代理端本地绑定的 IPv4 与端口” (BNDADDR/BNDPORT) ——
            val bndPort = upstream.localPort
            val bndAddrV4: ByteArray = (upstream.localAddress as? Inet4Address)?.address
                ?: try {
                    // 极端情形（local 为 v6），兜底给一个合法 IPv4（127.0.0.1）
                    InetAddress.getByName("127.0.0.1").address
                } catch (_: Exception) {
                    byteArrayOf(127,0,0,1)
                }


            val cliOut = BufferedOutputStream(output, 256 * 1024)



            val upIn  = BufferedInputStream(upstream.getInputStream(),   256 * 1024)
            val upOut = BufferedOutputStream(upstream.getOutputStream(), 256 * 1024)
            // DIRECT：若抓到了首包，先踢给上游
            if (layerMinus == null && firstData != null && firstData.isNotEmpty()) {
                try { upOut.write(firstData); upOut.flush() } catch (_: Exception) {}
            }


            // 之后再启动双泵（保持你现有的 onEof→shutdownOutput、onDone 收尾）
            val remaining = java.util.concurrent.atomic.AtomicInteger(2)
            val onBothDone = {
                if (remaining.decrementAndGet() == 0) {
                    try { cliOut.flush() } catch (_: Exception) {}
                    try { upOut.flush() }  catch (_: Exception) {}
                    try { upstream.close() } catch (_: Exception) {}
                    try { client.close() }   catch (_: Exception) {}
                    onConnClose(connId)
                }
            }

            // 上游 -> 客户端
            forwardTrafficAsync(
                upIn, cliOut,
                onDone = onBothDone,
                onEof  = { try { client.shutdownOutput() } catch (_: Exception) {} }
            )
            // 客户端 -> 上游：至少搬过 1B 才半关（防 prime-only 触发）
            forwardTrafficAsync(
                cliIn, upOut,
                onDone = onBothDone,
                onEof  = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
                minBytesBeforeEofCallback = 1
            )
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Error in handleSocks4", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }


    // ====== Prime metrics (shared by LM & DIRECT) ======
    private val primeAttempts = AtomicLong(0)
    private val primeHits     = AtomicLong(0)
    private val primeBytesSum = AtomicLong(0)
    private fun recordPrime(bytes: Int) {
        primeAttempts.incrementAndGet()
        if (bytes > 0) {
            primeHits.incrementAndGet()
            primeBytesSum.addAndGet(bytes.toLong())
        }
    }


    // ====== SOCKS5 (CONNECT + UDP ASSOCIATE) ======
    private fun handleSocks5UdpAssociate(client: Socket, output: OutputStream) {
        try {
            val udpSocket = DatagramSocket(0)
            val udpPort = udpSocket.localPort
            val response = byteArrayOf(
                0x05, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                (udpPort shr 8).toByte(), (udpPort and 0xFF).toByte()
            )
            output.write(response); output.flush()

            threadPoolExecutor.execute {
                val buffer = ByteArray(65507)
                while (true) {
                    try {
                        val packet = DatagramPacket(buffer, buffer.size)
                        udpSocket.receive(packet)

                        val data = packet.data
                        if (data[2].toInt() != 0) continue // no frag support

                        val (_, _, payloadOffset) = parseUdpHeader(data)
                        val payload = data.copyOfRange(payloadOffset, packet.length)

                        // echo back for demo; real impl should send out and await resp
                        val respData = wrapSocks5Udp(DatagramPacket(payload, payload.size, packet.socketAddress))
                        val clientResp = DatagramPacket(respData, respData.size, packet.socketAddress)
                        udpSocket.send(clientResp)
                    } catch (_: Exception) {}
                }
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "UDP associate failed", e)
            try { client.close() } catch (_: Exception) {}
        }
    }

    // 统一零等待 prime（LM/DIRECT/所有协议共用）：只读“已到达”的字节；不阻塞；带统计
    private fun capturePrimeNonBlocking(cliIn: BufferedInputStream, maxBytes: Int = 16 * 1024): ByteArray? {
        var n = 0
        return try {
            val avail = try { cliIn.available() } catch (_: Exception) { 0 }
            if (avail > 0) {
                val toRead = minOf(avail, maxBytes)
                val buf = ByteArray(toRead)
                n = cliIn.read(buf)
                if (n > 0) buf.copyOf(n) else null
            } else null
        } catch (_: Exception) {
            null
        } finally {
            // 复用你已存在的首包统计（若未引入，可按你之前的实现添加 recordPrime）
            try { recordPrime(n) } catch (_: Exception) {}
        }
    }

    private fun parseUdpHeader(data: ByteArray): Triple<String, Int, Int> {
        var offset = 3 // RSV(2)+FRAG
        val atyp = data[offset++].toInt()
        val destHost = when (atyp) {
            0x01 -> { val ip = data.copyOfRange(offset, offset + 4).joinToString(".") { (it.toInt() and 0xFF).toString() }; offset += 4; ip }
            0x03 -> { val len = data[offset++].toInt(); val domain = String(data.copyOfRange(offset, offset + len)); offset += len; domain }
            else -> "0.0.0.0"
        }
        val port = (data[offset++].toInt() shl 8) or (data[offset++].toInt() and 0xFF)
        return Triple(destHost, port, offset)
    }

    private fun wrapSocks5Udp(packet: DatagramPacket): ByteArray {
        val addr = packet.address.address
        val port = packet.port
        val header = ByteArray(3 + 1 + addr.size + 2)
        header[0] = 0x00; header[1] = 0x00; header[2] = 0x00
        header[3] = if (addr.size == 16) 0x04 else 0x01
        System.arraycopy(addr, 0, header, 4, addr.size)
        header[4 + addr.size] = (port shr 8).toByte()
        header[5 + addr.size] = (port and 0xFF).toByte()
        return header + packet.data.copyOfRange(0, packet.length)
    }

    private fun handleSocks5(client: Socket, input: InputStream, output: OutputStream, connId: Long) {
        try {
            // Greeting
            input.read() // VER
            val nMethods = input.read()
            val methods = ByteArray(nMethods); input.read(methods)
            output.write(byteArrayOf(0x05, 0x00)) // no-auth
            output.flush()

            // Request
            input.read() // VER
            val cmd = input.read()
            input.read() // RSV
            val atyp = input.read()

            val destHost = when (atyp) {
                0x01 -> { val ip = ByteArray(4); input.read(ip); ip.joinToString(".") { (it.toInt() and 0xFF).toString() } }
                0x03 -> { val len = input.read(); val domain = ByteArray(len); input.read(domain); String(domain) }
                else -> { try { client.close() } catch (_: Exception) {}; onConnClose(connId); return }
            }
            val port = (input.read() shl 8) or input.read()

            val okResp = byteArrayOf(0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0)
            when (cmd) {
                0x01 -> { // CONNECT
                    output.write(okResp); output.flush()
                    // 统一：分支前“微等待 prime”（5–10ms；复用握手流）
                    val cliIn = if (input is BufferedInputStream) input else BufferedInputStream(input, 256 * 1024)
                    val firstData = capturePrimeAdaptive(cliIn, client, stepMs = 5, maxRounds = 4, maxBytes = 16 * 1024)


                    val upstream: Socket? = if (layerMinus != null) {
                        layerMinus?.connectToLayerMinus(destHost, port.toString(), firstData)
                    } else {
                        try { Socket(destHost, port) } catch (_: Exception) { null }
                    }
                    if (upstream == null) {
                        try { client.close() } catch (_: Exception) {}
                        onConnClose(connId); return
                    }
                    setSocketPerfOptions(client, upstream)
                    try { upstream.soTimeout = 300 } catch (_: Exception) {} // CONNECT 首包容错


                    val upIn  = BufferedInputStream(upstream.getInputStream(),   256 * 1024)
                    val upOut = BufferedOutputStream(upstream.getOutputStream(), 256 * 1024)
                    val cliOut = BufferedOutputStream(output, 256 * 1024)

                    // DIRECT：若抓到了首包，先踢给上游
                    if (layerMinus == null && firstData != null && firstData.isNotEmpty()) {
                        try { upOut.write(firstData); upOut.flush() } catch (_: Exception) {}
                    }

                    val remaining = java.util.concurrent.atomic.AtomicInteger(2)
                    val onBothDone = {
                        if (remaining.decrementAndGet() == 0) {
                            try { cliOut.flush() } catch (_: Exception) {}
                            try { upOut.flush() }  catch (_: Exception) {}
                            try { upstream.close() } catch (_: Exception) {}
                            try { client.close() }   catch (_: Exception) {}
                            onConnClose(connId)
                        }
                    }

                    forwardTrafficAsync(
                        upIn, cliOut,
                        onDone = onBothDone,
                        onEof  = { try { client.shutdownOutput() } catch (_: Exception) {} }
                    )

                    forwardTrafficAsync(
                        cliIn, upOut,
                        onDone = onBothDone,
                        onEof  = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
                        minBytesBeforeEofCallback = 1   // ✅ LM 与 DIRECT 共用：防 0B EOF 误半关
                    )



                }
                0x03 -> { // UDP ASSOCIATE
                    handleSocks5UdpAssociate(client, output)
                    // Close will be logged when client disconnects; not handled here
                }
                else -> {
                    output.write(byteArrayOf(0x05, 0x07)) // Command not supported
                    output.flush()
                    try { client.close() } catch (_: Exception) {}
                    onConnClose(connId)
                }
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Error in handleSocks5", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }

    // ====== Notification ======
    private fun createNotification(): Notification {
        return Notification.Builder(this, "SocketChannel")
            .setContentTitle("Socket Server Running")
            .setContentText("Listening on port 8888")
            .setSmallIcon(R.drawable.stat_notify_sync)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                "SocketChannel",
                "Socket Background Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(serviceChannel)
        }
    }
}
