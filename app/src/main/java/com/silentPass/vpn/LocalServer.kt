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

    // ====== Server State ======
    private var serverThread: Thread? = null
    @Volatile private var isRunning = true
    private var layerMinus: LayerMinus? = null
    private var serverSocket: ServerSocket? = null
    private val LOG_TAG = "SocketServerService"

    // ====== ThreadPool (avoid per-conn thread explosion) ======
    private val threadCounter = AtomicInteger(0)
    private val threadPoolExecutor = ThreadPoolExecutor(
        10, 200, 60L, TimeUnit.SECONDS,
        SynchronousQueue<Runnable>(),
        ThreadFactory { r ->
            Thread(r).apply {
                name = "ProxyWorker-${threadCounter.incrementAndGet()}"
                isDaemon = true
                priority = Thread.NORM_PRIORITY
            }
        },
        ThreadPoolExecutor.CallerRunsPolicy()
    )

    // ====== Event-style metrics (print only on connection OPEN/CLOSE) ======
    private val activeConns = AtomicInteger(0)
    private val connSeq = AtomicLong(0)
    private fun logPoolSnapshot(event: String, connId: Long, note: String = "") {
        val q = threadPoolExecutor.queue
        Log.i(
            LOG_TAG,
            "[$event] conn#$connId " +
                    "activeConns=${activeConns.get()} " +
                    "pool={active:${threadPoolExecutor.activeCount}, size:${threadPoolExecutor.poolSize}/${threadPoolExecutor.maximumPoolSize}, largest:${threadPoolExecutor.largestPoolSize}} " +
                    "tasks={submitted:${threadPoolExecutor.taskCount}, completed:${threadPoolExecutor.completedTaskCount}} " +
                    "queue.size=${q.size} $note"
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
        bufferSize: Int = 128 * 1024,
        onDone: (() -> Unit)? = null,
        onEof: (() -> Unit)? = null,
        minBytesBeforeEofCallback: Long = 0   // 新增：EOF 回调的最小搬运字节数
    ): Future<*> {
        return threadPoolExecutor.submit {
            Log.d(LOG_TAG, "Start forwarding from ${input.javaClass.simpleName} to ${output.javaClass.simpleName}")
            var src: java.nio.channels.ReadableByteChannel? = null
            var dst: java.nio.channels.WritableByteChannel? = null
            try {

                Log.d(LOG_TAG, "input available bytes: ${input.available()}")
                src = Channels.newChannel(input)
                dst = Channels.newChannel(output)
                val buf = ByteBuffer.allocateDirect(bufferSize)
                var totalBytes = 0L             // 该方向由本任务实际搬运的字节数
                var sinceLastFlush = 0L
                val WARMUP_LIMIT = 64 * 1024     // small-flow threshold
                val FLUSH_THRESHOLD = 64 * 1024  // batch flush in bulk flow

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
                        Log.d(LOG_TAG, "EOF reached after forwarding $totalBytes bytes")
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

                        // 1) 小流阶段：每块都刷
                        // 2) 大流阶段：累计到阈值再刷
                        // 3) 尾部微小块：立即刷，防止“只差一点点”却被憋住
                        val tinyChunk = wroteThisChunk in 1 until 32 * 1024

                        if (inWarmup || sinceLastFlush >= FLUSH_THRESHOLD || tinyChunk) {
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
                try { input.close() } catch (_: Exception) {}
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
                this.layerMinus = null      //LayerMinus(startVPNData)

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
                serverSocket = ServerSocket(8888, 256)
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
                        handleHttpsConnect(client, requestLine, connId)
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

            // DIRECT must write firstData first, then start bidirectional pumps
            if (layerMinus == null) {
                BufferedWriter(OutputStreamWriter(upstream.getOutputStream())).apply {
                    write(requestBody); flush()
                }
            }

            val upIn  = BufferedInputStream(upstream.getInputStream(),   128 * 1024)
            val upOut = BufferedOutputStream(upstream.getOutputStream(), 128 * 1024)
            val cliIn  = BufferedInputStream(client.getInputStream(),    128 * 1024)
            val cliOut = BufferedOutputStream(client.getOutputStream(),  128 * 1024)

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
            forwardTrafficAsync(cliIn, upOut,  onDone = onBothDone) // client   -> upstream
        } catch (e: Exception) {
            Log.e(LOG_TAG, "HTTP proxy error", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }

    // ====== HTTPS (CONNECT) ======
    private fun handleHttpsConnect(client: Socket, requestLine: String, connId: Long) {
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

            // Read client's TLS ClientHello as firstData
            val cliInStream: InputStream = client.getInputStream()
            val firstData: ByteArray? = readFirstChunkOrNull(cliInStream)
            Log.d(LOG_TAG, "CONNECT firstData length = ${firstData?.size ?: 0}")

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

            val upIn   = BufferedInputStream(upstream.getInputStream(),   128 * 1024)
            val upOutB = BufferedOutputStream(upstream.getOutputStream(), 128 * 1024)
            val cliOut = BufferedOutputStream(client.getOutputStream(),   128 * 1024)

            // DIRECT: push the captured firstData immediately so server can handshake
            if (layerMinus == null && firstData != null && firstData.isNotEmpty()) {
                try { upOutB.write(firstData); upOutB.flush() } catch (_: Exception) {}
            }

            val remaining = AtomicInteger(2)
            val onBothDone = {
                if (remaining.decrementAndGet() == 0) {
                    try { cliOut.flush() } catch (_: Exception) {}
                    try { upOutB.flush() } catch (_: Exception) {}
                    try { upstream.close() } catch (_: Exception) {}
                    try { client.close() }   catch (_: Exception) {}
                    onConnClose(connId)
                }
            }
            // Upstream -> Client：上游写完，通知客户端“我不再写了”
            forwardTrafficAsync(
                upIn, cliOut,
                onDone = onBothDone,
                onEof  = { try { client.shutdownOutput() } catch (_: Exception) {} }
            )
            // Client -> Upstream：客户端写完，通知上游“我不再写了”
            forwardTrafficAsync(
                cliInStream, upOutB,
                onDone = onBothDone,
                onEof  = { try { upstream.shutdownOutput() } catch (_: Exception) {} }
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
            val destHostOrIp = if (isSocks4a) {
                val sb = StringBuilder(); var b: Int
                while (input.read().also { b = it } != 0 && b != -1) sb.append(b.toChar())
                sb.toString()
            } else {
                ip.joinToString(".") { (it.toInt() and 0xFF).toString() } // IPv4 字符串
            }

            // —— 按 SOCKS4 规范：只允许 IPv4；强制解析到 IPv4，否则失败 8 字节 ——
            val targetInet4: Inet4Address? = try {
                val all = InetAddress.getAllByName(destHostOrIp)
                all.firstOrNull { it is Inet4Address } as? Inet4Address
            } catch (_: Exception) { null }

            Log.d(LOG_TAG, "SOCKS4 req -> host=$destHostOrIp (v4=${targetInet4?.hostAddress}) port=$port")

            if (targetInet4 == null) {
                try { output.write(byteArrayOf(0x00, 0x5b, 0,0, 0,0,0,0)); output.flush() } catch (_: Exception) {}
                client.close(); onConnClose(connId); return
            }

            // —— 建立上游连接：直连用 IPv4 地址；LayerMinus 也传 IPv4 字符串 ——
            val upstream: Socket? = if (layerMinus != null) {
                layerMinus?.connectToLayerMinus(targetInet4.hostAddress, port.toString(), null)
            } else {
                try { Socket(targetInet4, port) } catch (_: Exception) { null }
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

            val granted = byteArrayOf(
                0x00, 0x5a,
                (bndPort shr 8).toByte(), (bndPort and 0xFF).toByte(),
                bndAddrV4[0], bndAddrV4[1], bndAddrV4[2], bndAddrV4[3]
            )
            try {
                Log.d(LOG_TAG, "SOCKS4 granted -> BND=${bndAddrV4[0].toInt() and 0xFF}.${bndAddrV4[1].toInt() and 0xFF}.${bndAddrV4[2].toInt() and 0xFF}.${bndAddrV4[3].toInt() and 0xFF}:$bndPort")
                output.write(granted)
                output.flush()
            } catch (_: Exception) {}

            // —— 双向转发：复用握手时的 input，避免预读首包丢失 ——
            val upIn  = BufferedInputStream(upstream.getInputStream(),   128 * 1024)
            val upOut = BufferedOutputStream(upstream.getOutputStream(), 128 * 1024)
            val cliIn  = if (input is BufferedInputStream) input else BufferedInputStream(input, 128 * 1024)
            val cliOut = BufferedOutputStream(output, 128 * 1024)

            // 新：非阻塞 prime（仅在有“已到达数据”时立刻踢一下；否则不等待）
            try {
                val avail = try { cliIn.available() } catch (_: Exception) { 0 }
                if (avail > 0) {
                    val kick = ByteArray(minOf(avail, 16 * 1024))
                    val n = cliIn.read(kick)
                    if (n > 0) {
                        upOut.write(kick, 0, n)
                        upOut.flush()
                        Log.d(LOG_TAG, "SOCKS4 prime(non-block) kick $n bytes")
                    }
                }
            } catch (_: Exception) { /* 忽略 prime 异常 */ }

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
                    if (layerMinus != null) {
                        // Try to capture firstData quickly (short timeout) to package to LM
                        val bufferedInput = BufferedInputStream(input)
                        bufferedInput.mark(8192)
                        val peekBuf = ByteArray(4096)
                        var firstPacketSize = 0
                        client.soTimeout = 100
                        try { firstPacketSize = bufferedInput.read(peekBuf) }
                        catch (_: SocketTimeoutException) { firstPacketSize = 0 }
                        finally { client.soTimeout = 0 }
                        if (firstPacketSize > 0) bufferedInput.reset()
                        val firstData = if (firstPacketSize > 0) {
                            val data = ByteArray(firstPacketSize)
                            bufferedInput.read(data); data
                        } else null

                        val upstream = layerMinus?.connectToLayerMinus(destHost, port.toString(), firstData)
                        if (upstream == null) {
                            Log.e(LOG_TAG, "LayerMinus upstream failed $destHost:$port")
                            try { client.close() } catch (_: Exception) {}
                            onConnClose(connId); return
                        }

                        setSocketPerfOptions(client, upstream)

                        val upIn  = BufferedInputStream(upstream.getInputStream(),   128 * 1024)
                        val upOut = BufferedOutputStream(upstream.getOutputStream(), 128 * 1024)
                        val cliIn  = bufferedInput
                        val cliOut = BufferedOutputStream(output,                   128 * 1024)

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

                        forwardTrafficAsync(
                            upIn, cliOut,
                            onDone = onBothDone,
                            onEof  = { try { client.shutdownOutput() } catch (_: Exception) {} }
                        )
                        forwardTrafficAsync(
                            cliIn, upOut,
                            onDone = onBothDone,
                            onEof  = { try { upstream.shutdownOutput() } catch (_: Exception) {} }
                        )

                    } else {
                        val target = try { Socket(destHost, port) } catch (_: Exception) { null }
                        if (target == null) {
                            try { client.close() } catch (_: Exception) {}
                            onConnClose(connId); return
                        }

                        setSocketPerfOptions(client, target)

                        val upIn  = BufferedInputStream(target.getInputStream(),   128 * 1024)
                        val upOut = BufferedOutputStream(target.getOutputStream(), 128 * 1024)
                        val cliIn  = BufferedInputStream(input,                  128 * 1024)
                        val cliOut = BufferedOutputStream(output,                 128 * 1024)

                        val remaining = AtomicInteger(2)
                        val onBothDone = {
                            if (remaining.decrementAndGet() == 0) {
                                try { cliOut.flush() } catch (_: Exception) {}
                                try { upOut.flush() }  catch (_: Exception) {}
                                try { target.close() }  catch (_: Exception) {}
                                try { client.close() }  catch (_: Exception) {}
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
                            onEof  = { try { target.shutdownOutput() } catch (_: Exception) {} }
                        )
                    }
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
