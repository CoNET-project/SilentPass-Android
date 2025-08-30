package com.silentPass.vpn.vpn2socks

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.Socket
import kotlin.random.Random

class TCPConnection(
    private val key: String,
    private val mtu: Int,
    private val packetWriter: (List<ByteArray>, List<Int>) -> Unit,
    private val dns: DNSInterceptor,
    private val socksEndpoint: SocksEndpoint,
    private val bypassDirect: Boolean
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var upstream: Socket? = null
    private var upstreamWriter: java.io.OutputStream? = null
    private var upstreamReader: java.io.InputStream? = null

    // 添加同步锁和状态标志
    private val writeLock = Mutex()
    private var isClosed = false

    private var clientSeq0: Int? = null
    private var clientNextSeq: Int = 0
    private var serverSeq: Int = Random.nextInt(0, Int.MAX_VALUE)
    private var established: Boolean = false

    fun isClosed(): Boolean = isClosed

    private val LOG_TAG = "TCPConnection"
    private val pendingLock = Mutex()
    private val pending = ArrayDeque<ByteArray>()

    // 1) 替换 onTcp(...)：把“未建好上游时的 payload”先入队；建好后再冲刷
    fun onTcp(ip: IPv4Packet, tcp: TCPSegment) {
        if (isClosed) {
            android.util.Log.w(LOG_TAG, "Connection already closed for $key")
            return
        }

        // SYN：记录 client 初始 seq，启动上游连接，并立即回 SYN-ACK
        if (tcp.isSYN && !tcp.isACK) {
            val domain = dns.lookupDomain(ip.dst)
            clientSeq0 = tcp.seq.toInt()
            clientNextSeq = clientSeq0!! + 1
            scope.launch { establishAndAck(ip, tcp, domain) }

            val synAck = IpBuilders.tcpPayloadFromServer(
                src = ip.dst, dst = ip.src,
                srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                payload = ByteArray(0),
                seq = serverSeq,
                ack = clientNextSeq,
                flags = 0x12, // SYN|ACK
                window = 65535
            )
            packetWriter(listOf(synAck), listOf(ConnectionManager.PROTO_IPV4))
            serverSeq += 1
            return
        }

        // 客户端对我方 SYN-ACK 的纯 ACK
        if (!established && tcp.isACK && !tcp.isSYN && tcp.payload.isEmpty()) {
            if (tcp.ack.toInt() == serverSeq) {
                established = true
                android.util.Log.d(LOG_TAG, "3-way handshake established for $key")
            }
            return
        }

        // FIN
        if (tcp.isFIN) {
            android.util.Log.d(LOG_TAG, "FIN received for $key")
            closeConnection()
            val finAck = IpBuilders.tcpPayloadFromServer(
                src = ip.dst, dst = ip.src,
                srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                payload = ByteArray(0),
                seq = serverSeq,
                ack = clientNextSeq + 1,
                flags = 0x11, // FIN|ACK
                window = 65535
            )
            packetWriter(listOf(finAck), listOf(ConnectionManager.PROTO_IPV4))
            return
        }

        // RST
        if (tcp.isRST) {
            android.util.Log.d(LOG_TAG, "RST received for $key")
            closeConnection()
            return
        }

        // 已建立：有上行数据
        if (established && tcp.payload.isNotEmpty()) {


            Log.d(LOG_TAG, "Client->Server: ${tcp.payload.size} bytes for $key")
            clientNextSeq += tcp.payload.size

            // 先将数据加入队列
            scope.launch {
                pendingLock.withLock {
                    pending.addLast(tcp.payload.copyOf())
                }

                // 如果上游已连接，立即尝试发送
                if (upstreamWriter != null) {
                    tryFlushUpstream()
                    // 只有在成功发送后才回 ACK
                    val ackPacket = IpBuilders.tcpPayloadFromServer(
                        src = ip.dst, dst = ip.src,
                        srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                        payload = ByteArray(0),
                        seq = serverSeq,
                        ack = clientNextSeq,
                        flags = 0x10, // ACK
                        window = 65535
                    )
                    packetWriter(listOf(ackPacket), listOf(ConnectionManager.PROTO_IPV4))
                } else {
                    // 如果上游未连接，延迟 ACK
                    Log.d(LOG_TAG, "Delaying ACK until upstream is ready")
                }
            }
            return
        }
    }

    // 2) 新增一个内部方法：把 pending 队列冲刷到上游（需在 IO 线程里调用）
    private suspend fun tryFlushUpstream() {
        val out = upstreamWriter ?: return
        while (true) {
            val chunk: ByteArray? = pendingLock.withLock {
                if (pending.isEmpty()) null else pending.removeFirst()
            }
            if (chunk == null) break

            Log.d(LOG_TAG, "Writing ${chunk.size} bytes to upstream")
            writeLock.withLock {
                if (isClosed) return
                out.write(chunk)
                out.flush()
            }
            Log.d(LOG_TAG, "Successfully wrote to upstream")
        }
    }

    private fun isTLSHandshake(data: ByteArray): Boolean {
        // TLS handshake starts with 0x16 (handshake) followed by version
        return data.size >= 3 && data[0] == 0x16.toByte() &&
                (data[1] == 0x03.toByte()) // TLS 1.x
    }
    private fun closeConnection() {
        if (isClosed) return
        isClosed = true

        scope.launch {
            try {
                upstream?.close()
            } catch (_: Throwable) {}
            upstream = null
            upstreamWriter = null
            upstreamReader = null
        }

        scope.cancel()
    }

    private suspend fun establishAndAck(ip: IPv4Packet, syn: TCPSegment, domain: String?) {
        try {
            val port = syn.dstPort
            val hostForDial = if (domain != null) {
                android.util.Log.d(LOG_TAG, "Using domain: $domain for SOCKS dial")
                domain
            } else {
                android.util.Log.d(LOG_TAG, "No domain found, using IP: ${ip.dst}")
                ip.dst.toString()
            }

            val s = if (bypassDirect) {
                android.util.Log.d(LOG_TAG, "Direct dial $hostForDial:$port (bypass)")
                val socket = java.net.Socket()
                socket.tcpNoDelay = true

                // CRITICAL FIX: Protect BEFORE connect, not after
                val protectResult = Vpn2SocksService.protectSocket(socket)
                android.util.Log.d(LOG_TAG, "Socket protection result: $protectResult")

                // Now connect
                socket.connect(java.net.InetSocketAddress(hostForDial, port), 15000)
                socket
            } else {
                android.util.Log.d(LOG_TAG, "Dial SOCKS ${socksEndpoint.host}:${socksEndpoint.port} for $hostForDial:$port")
                val socket = SocksClient(socksEndpoint).dial(hostForDial, port)
                socket.tcpNoDelay = true
                android.util.Log.d(LOG_TAG, "SOCKS dial completed successfully for $hostForDial:$port")
                socket
            }

            upstream = s
            upstreamWriter = s.getOutputStream()
            upstreamReader = s.getInputStream()

            // Flush any pending data
            try {
                tryFlushUpstream()
            } catch (e: Exception) {
                android.util.Log.e(LOG_TAG, "Flush pending failed: ${e.message}")
                closeConnection()
                return
            }

            android.util.Log.d(LOG_TAG, "Starting downstream loop for $key")
            scope.launch { downstreamLoop(ip, syn) }
            android.util.Log.d(LOG_TAG, "SOCKS${if (bypassDirect) "(direct override)" else ""} connected, start downstream pump")
        } catch (t: Throwable) {
            android.util.Log.e(LOG_TAG, "Upstream connect failed for $key: ${t.javaClass.simpleName}: ${t.message}", t)
            closeConnection()
        }
    }

    private suspend fun downstreamLoop(initialIp: IPv4Packet, syn: TCPSegment) {
        val inp = upstreamReader ?: return
        val mss = (mtu - 40).coerceAtLeast(536)
        val buf = ByteArray(32 * 1024)

        try {
            while (!isClosed) {
                val n = withContext(Dispatchers.IO) { inp.read(buf) }
                if (n <= 0) {
                    android.util.Log.i(LOG_TAG, "Downstream EOF for $key")
                    break
                }
                android.util.Log.d(LOG_TAG, "Server->Client: $n bytes for $key")
                if (!established) continue

                var off = 0
                while (off < n && !isClosed) {
                    val take = kotlin.math.min(mss, n - off)
                    val payload = buf.copyOfRange(off, off + take)

                    val out = IpBuilders.tcpPayloadFromServer(
                        src = initialIp.dst, dst = initialIp.src,
                        srcPort = syn.dstPort, dstPort = syn.srcPort,
                        payload = payload,
                        seq = serverSeq,
                        ack = clientNextSeq,
                        flags = 0x18, // PSH|ACK
                        window = 65535
                    )
                    packetWriter(listOf(out), listOf(ConnectionManager.PROTO_IPV4))
                    serverSeq += take
                    off += take
                }
            }
        } catch (e: Exception) {
            android.util.Log.e(LOG_TAG, "Downstream loop error: ${e.message}")
        } finally {
            closeConnection()
        }
    }
}