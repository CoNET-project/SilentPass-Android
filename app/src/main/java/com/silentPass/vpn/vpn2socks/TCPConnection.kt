package com.silentPass.vpn.vpn2socks

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random

class TCPConnection(
    private val key: String,
    private val mtu: Int,
    private val packetWriter: (List<ByteArray>, List<Int>) -> Unit,
    private val dns: DNSInterceptor,
    private val socksEndpoint: SocksEndpoint,
    private val bypassDirect: Boolean
) {

    private data class ConnectionStats(
        var totalPackets: Long = 0,
        var outOfOrderPackets: Long = 0,
        var retransmittedPackets: Long = 0,
        var droppedPackets: Long = 0,
        var bufferHits: Long = 0,
        var bufferMisses: Long = 0
    ) {
        fun getOutOfOrderRatio() = if (totalPackets > 0)
            outOfOrderPackets.toDouble() / totalPackets else 0.0

        fun logStats(tag: String, key: String) {
            if (totalPackets % 100 == 0L) {  // 每100个包记录一次
                Log.i(tag, "Stats for $key: OOO=${getOutOfOrderRatio() * 100}%, " +
                        "Retrans=$retransmittedPackets, Dropped=$droppedPackets, " +
                        "BufferHit=${bufferHits}/${bufferHits + bufferMisses}")
            }
        }
    }

    private val stats = ConnectionStats()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // === Upstream socket / IO ===
    private var upstream: Socket? = null
    private var upstreamWriter: java.io.OutputStream? = null
    private var upstreamReader: java.io.InputStream? = null
    // === 乱序重组缓冲（加锁 + 动态尺寸限制）===
    private data class Segment(val seq: Long, val data: ByteArray, val timestamp: Long = System.currentTimeMillis())

    // 动态调整缓冲区大小
    private var oooBufferLimit = 256 * 1024  // 初始256KB
    private val OOO_BUFFER_MIN = 128 * 1024
    private val OOO_BUFFER_MAX = 512 * 1024
    private var oooBufferHitCount = 0
    private var oooBufferMissCount = 0

    // 自适应调整缓冲区大小
    private fun adjustOOOBufferSize() {
        if (oooBufferHitCount > oooBufferMissCount * 2 && oooBufferLimit < OOO_BUFFER_MAX) {
            oooBufferLimit = minOf(oooBufferLimit * 2, OOO_BUFFER_MAX)
            Log.d(LOG_TAG, "Increased OOO buffer to ${oooBufferLimit / 1024}KB for $key")
        } else if (oooBufferMissCount > oooBufferHitCount * 2 && oooBufferLimit > OOO_BUFFER_MIN) {
            oooBufferLimit = maxOf(oooBufferLimit / 2, OOO_BUFFER_MIN)
            Log.d(LOG_TAG, "Decreased OOO buffer to ${oooBufferLimit / 1024}KB for $key")
        }
        // 重置计数器
        if (oooBufferHitCount + oooBufferMissCount > 100) {
            oooBufferHitCount = 0
            oooBufferMissCount = 0
        }
    }

    // === Synchronization & State ===
    private val writeLock = Mutex()
    private val stateLock = Mutex()
    @Volatile private var isClosed = false
    fun isClosed(): Boolean = isClosed

    // 连接阶段状态机：两道“门闩”都好后才切 STREAMING
    private enum class Phase { SYN, HANDSHAKE_ACKED, SOCKS_PRIMED, STREAMING, HALF_CLOSED_LOCAL, HALF_CLOSED_REMOTE, CLOSED }
    @Volatile private var phase: Phase = Phase.SYN
    @Volatile private var handshakeAcked = false
    @Volatile private var socksPrimed = false
    private fun canStream(): Boolean = handshakeAcked && socksPrimed && phase != Phase.CLOSED

    // === TCP seq 状态 ===
    private var clientSeq0: Long? = null
    private var clientNextSeq: Long = 0L
    private var serverSeq: Long = Random.nextInt(0, Int.MAX_VALUE).toLong()

    // === 旧的 established 概念由状态机取代，保留变量以兼容原逻辑 ===
    @Deprecated("Use phase/handshakeAcked/socksPrimed")
    private var established: Boolean = false

    private val LOG_TAG = "TCPConnection"

    // === Client->Server 缓冲 ===
    private val pendingLock = Mutex()
    private val pending = ArrayDeque<ByteArray>()

    // 握手前（客户端→服务端）首包/早到数据缓冲（替代“Data received before handshake complete”告警）
    private val preHandshakeBuf = ByteArrayOutputStream(32 * 1024)
    private val preHandshakeLock = Mutex()
    private val PRE_HANDSHAKE_BUF_LIMIT = 32 * 1024

    // Downstream “Prime” 缓冲（服务端→客户端）——保留原有逻辑
    private val downPrimeLock = Mutex()
    private var downPrime: ByteArray? = null


    private val outOfOrderLock = Mutex()
    private val outOfOrderSegments = mutableListOf<Segment>()
    private val OOO_BUFFER_LIMIT_BYTES = 128 * 1024

    // === 半关闭/关停 ===
    @Volatile private var clientHalfClosed = false
    @Volatile private var pendingShutdown = false
    @Volatile private var downstreamStarted = false
    private val closedOnce = AtomicBoolean(false)

    // === 小包写合并，减少 write()/flush() 调用频率 ===
    private class SmallWriteCoalescer(private val targetBytes: Int = 2048) {
        private val buf = ByteArrayOutputStream()
        @Synchronized fun offer(bytes: ByteArray, writer: (ByteArray) -> Boolean) {
            if (bytes.isEmpty()) return
            if (buf.size() > 0 && buf.size() + bytes.size >= targetBytes) {
                flush(writer)
            }
            buf.write(bytes)
            if (buf.size() >= targetBytes) {
                flush(writer)
            }
        }
        @Synchronized fun flush(writer: (ByteArray) -> Boolean) {
            if (buf.size() == 0) return
            val arr = buf.toByteArray()
            buf.reset()
            writer(arr)
        }
    }
    private val coalescer = SmallWriteCoalescer(2048)

    // =============== Main Entry ===============
    fun onTcp(ip: IPv4Packet, tcp: TCPSegment) {
        scope.launch {
            processPacket(ip, tcp)
        }
    }

    private suspend fun processPacket(ip: IPv4Packet, tcp: TCPSegment) {
        if (isClosed) {
            Log.w(LOG_TAG, "Connection already closed for $key")
            return
        }

        // RST: Immediate close
        if (tcp.isRST) {
            Log.d(LOG_TAG, "RST received for $key")
            closeConnection()
            return
        }

        // SYN (client -> us)
        if (tcp.isSYN && !tcp.isACK) {
            val domain = dns.lookupDomain(ip.dst)
            clientSeq0 = tcp.seq.toLong() and 0xFFFFFFFFL
            clientNextSeq = (clientSeq0!! + 1L) and 0xFFFFFFFFL

            scope.launch { establishUpstream(ip, tcp, domain) }

            val synAck = IpBuilders.tcpPayloadFromServer(
                src = ip.dst, dst = ip.src,
                srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                payload = ByteArray(0),
                seq = serverSeq.toInt(),
                ack = clientNextSeq.toInt(),
                flags = 0x12, // SYN | ACK
                window = 65535
            )
            packetWriter(listOf(synAck), listOf(ConnectionManager.PROTO_IPV4))
            serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL
            return
        }

        // Handle ACK that completes handshake
        if (!handshakeAcked && tcp.isACK && !tcp.isSYN) {
            val ackNum = tcp.ack.toLong() and 0xFFFFFFFFL
            if (ackNum == serverSeq) {
                stateLock.withLock {
                    handshakeAcked = true
                    phase = Phase.HANDSHAKE_ACKED
                    established = true // 兼容旧逻辑
                }
                Log.d(LOG_TAG, "3-way handshake established for $key")

                // 刷新握手前缓冲的客户端数据（如果有）
                flushPreHandshakeBufferToPending()

                tryStartDownstream(ip, tcp)

                if (tcp.payload.isNotEmpty()) {
                    Log.d(LOG_TAG, "Processing ${tcp.payload.size} bytes of early data with handshake ACK")
                    handleEstablishedData(ip, tcp)
                }

                if (tcp.isFIN) {
                    handleFIN(ip, tcp)
                }
                return
            }
        }

        // Handle established/streaming
        if (handshakeAcked) {
            if (tcp.payload.isNotEmpty()) {
                handleEstablishedData(ip, tcp)
            }
            if (tcp.isFIN) {
                handleFIN(ip, tcp)
            }
            return
        }

        // Handle FIN before establishment (connection abort)
        if (tcp.isFIN) {
            Log.d(LOG_TAG, "FIN received before establishment for $key")
            clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
            sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
            closeConnection()
            return
        }

        // 握手未完成：不再告警，改为缓冲
        if (tcp.payload.isNotEmpty()) {
            bufferPreHandshakeClientData(tcp.payload)
        }
    }

    // ======== 握手前客户端数据缓冲 / 刷新 ========
    private suspend fun bufferPreHandshakeClientData(bytes: ByteArray) {
        preHandshakeLock.withLock {
            if (preHandshakeBuf.size() + bytes.size <= PRE_HANDSHAKE_BUF_LIMIT) {
                preHandshakeBuf.write(bytes)
                Log.d(LOG_TAG, "Buffered pre-handshake ${bytes.size}B (total=${preHandshakeBuf.size()}) for $key")
            } else {
                Log.w(LOG_TAG, "Pre-handshake buffer overflow, drop=${bytes.size}B for $key")
            }
        }
    }

    private suspend fun flushPreHandshakeBufferToPending() {
        val arr = preHandshakeLock.withLock {
            if (preHandshakeBuf.size() == 0) null
            else preHandshakeBuf.toByteArray().also { preHandshakeBuf.reset() }
        } ?: return

        // 将缓冲的握手前数据整体入队并推进 seq
        pendingLock.withLock { pending.addLast(arr) }
        clientNextSeq = (clientNextSeq + arr.size.toLong()) and 0xFFFFFFFFL
        Log.d(LOG_TAG, "Flushed pre-handshake ${arr.size}B into upstream queue for $key")
        tryFlushUpstream()
    }

    // Extract FIN handling to a separate method for clarity
    private suspend fun handleFIN(ip: IPv4Packet, tcp: TCPSegment) {
        Log.d(LOG_TAG, "FIN received for $key (client half-close)")
        clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
        sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())

        stateLock.withLock {
            clientHalfClosed = true
            pendingShutdown = true
            if (phase != Phase.CLOSED) phase = Phase.HALF_CLOSED_LOCAL
        }

        tryFlushUpstream()
    }

    private suspend fun smartDropSegment(newSeq: Long, newSize: Int) {
        outOfOrderLock.withLock {
            if (outOfOrderSegments.isEmpty()) return@withLock

            // 策略1: 丢弃最旧的段
            val now = System.currentTimeMillis()
            val oldestIndex = outOfOrderSegments.indices.minByOrNull { index ->
                outOfOrderSegments[index].timestamp
            }

            if (oldestIndex != null && now - outOfOrderSegments[oldestIndex].timestamp > 500) {
                val dropped = outOfOrderSegments.removeAt(oldestIndex)
                Log.d(LOG_TAG, "Dropped oldest segment seq=${dropped.seq} age=${now - dropped.timestamp}ms for $key")
                stats.droppedPackets++
                return@withLock
            }

            // 策略2: 丢弃离期望序列号最远的段
            val farthestIndex = outOfOrderSegments.indices.maxByOrNull { index ->
                kotlin.math.abs(outOfOrderSegments[index].seq - clientNextSeq).toDouble()
            }

            if (farthestIndex != null) {
                val dropped = outOfOrderSegments.removeAt(farthestIndex)
                Log.d(LOG_TAG, "Dropped farthest segment seq=${dropped.seq} for $key")
                stats.droppedPackets++
            }
        }
    }

    private var lastTripleDupAckTime = 0L
    private fun sendTripleDupAck(ip: IPv4Packet, tcp: TCPSegment) {
        val now = System.currentTimeMillis()
        if (now - lastTripleDupAckTime > 100) {  // 限制频率
            repeat(3) {
                sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
            }
            lastTripleDupAckTime = now
            Log.d(LOG_TAG, "Sent triple duplicate ACK for fast retransmit, expect seq=$clientNextSeq for $key")
        }
    }

    // =============== Handle Established Data ===============
    private suspend fun handleEstablishedData(ip: IPv4Packet, tcp: TCPSegment) {
        val segSeq = tcp.seq.toLong() and 0xFFFFFFFFL
        val dataLen = tcp.payload.size.toLong()
        val segEnd = (segSeq + dataLen) and 0xFFFFFFFFL
        val expect = clientNextSeq

        when {
            segSeq == expect -> {
                // 顺序包 - 优化路径
                handleInOrderPacket(ip, tcp, segEnd)
            }
            isSeqBefore(segSeq, expect) -> {
                // 旧段或部分重传
                handleRetransmission(ip, tcp, segSeq, segEnd, expect)
            }
            else -> {
                // 乱序包 - 智能处理
                handleOutOfOrderPacket(ip, tcp, segSeq, expect)
            }
        }
    }

    private suspend fun handleRetransmission(
        ip: IPv4Packet,
        tcp: TCPSegment,
        segSeq: Long,
        segEnd: Long,
        expect: Long
    ) {
        if (isSeqBefore(segEnd, expect)) {
            // 完全重复的段
            Log.d(LOG_TAG, "Duplicate segment seq=$segSeq expect=$expect, ACK for $key")
            sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
            stats.retransmittedPackets++
        } else {
            // 部分重传
            val overlap = (expect - segSeq).toInt()
            val newData = tcp.payload.copyOfRange(overlap, tcp.payload.size)
            Log.d(LOG_TAG, "Partial retrans: ${newData.size} new bytes for $key")

            clientNextSeq = segEnd
            pendingLock.withLock { pending.addLast(newData) }
            tryFlushUpstream()
            sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
            stats.retransmittedPackets++
        }
    }

    private suspend fun handleInOrderPacket(ip: IPv4Packet, tcp: TCPSegment, segEnd: Long) {
        Log.d(LOG_TAG, "Client->Server (in-order): ${tcp.payload.size} bytes for $key")
        clientNextSeq = segEnd
        stats.totalPackets++

        pendingLock.withLock {
            pending.addLast(tcp.payload.copyOf())
        }
        tryFlushUpstream()

        // 尝试释放缓冲的乱序段
        deliverBufferedSegments(ip, tcp)
        oooBufferHitCount++
        stats.bufferHits++

        // 发送 ACK
        sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())

        // 记录统计信息
        stats.logStats(LOG_TAG, key)
    }

    private suspend fun handleOutOfOrderPacket(ip: IPv4Packet, tcp: TCPSegment, segSeq: Long, expect: Long) {
        val gap = segSeq - expect
        val isReasonableGap = gap > 0 && gap < 65536  // 64KB窗口内认为合理

        if (!isReasonableGap) {
            Log.w(LOG_TAG, "Dropping far out-of-order segment seq=$segSeq expect=$expect gap=$gap for $key")
            oooBufferMissCount++
            stats.droppedPackets++
            sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
            return
        }

        Log.d(LOG_TAG, "Out-of-order segment seq=$segSeq expect=$expect, buffering for $key")
        stats.outOfOrderPackets++

        outOfOrderLock.withLock {
            // 清理过期段（超过1秒的认为丢失）
            val now = System.currentTimeMillis()
            val sizeBefore = outOfOrderSegments.size
            outOfOrderSegments.removeAll { segment ->
                (now - segment.timestamp) > 1000
            }
            if (sizeBefore > outOfOrderSegments.size) {
                Log.d(LOG_TAG, "Cleaned ${sizeBefore - outOfOrderSegments.size} expired segments")
            }

            // 检查缓冲区大小
            val currentBytes = outOfOrderSegments.sumOf { it.data.size } + tcp.payload.size
            if (currentBytes <= oooBufferLimit) {
                // 检查是否已存在
                val exists = outOfOrderSegments.any { it.seq == segSeq }
                if (!exists) {
                    // 插入并保持有序
                    val segment = Segment(segSeq, tcp.payload.copyOf(), System.currentTimeMillis())

                    // 使用二分查找找到插入位置
                    var insertPos = 0
                    for (i in outOfOrderSegments.indices) {
                        if (outOfOrderSegments[i].seq > segSeq) {
                            insertPos = i
                            break
                        }
                        insertPos = i + 1
                    }
                    outOfOrderSegments.add(insertPos, segment)

                    Log.d(LOG_TAG, "Buffered out-of-order segment, buffer size=${outOfOrderSegments.size} " +
                            "(bytes=$currentBytes/${oooBufferLimit}) for $key")

                    // 触发快速重传机制
                    if (outOfOrderSegments.size >= 3) {
                        sendTripleDupAck(ip, tcp)
                    }
                }
            } else {
                // 缓冲区满，智能丢弃
                smartDropSegment(segSeq, tcp.payload.size)
                oooBufferMissCount++
                stats.bufferMisses++
            }
        }

        // 定期调整缓冲区大小
        if ((oooBufferHitCount + oooBufferMissCount) % 50 == 0) {
            adjustOOOBufferSize()
        }

        // 发送重复 ACK
        sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
    }


    // TCP sequence number comparison (handles wraparound)
    private fun isSeqBefore(seq1: Long, seq2: Long): Boolean {
        val diff = (seq1 - seq2) and 0xFFFFFFFFL
        return diff > 0x80000000L
    }

    private suspend fun deliverBufferedSegments(ip: IPv4Packet, tcp: TCPSegment) {
        var delivered = 0
        val maxDelivery = 10  // 限制每次最多释放10个段，避免阻塞

        while (delivered < maxDelivery) {
            val segment = outOfOrderLock.withLock {
                if (outOfOrderSegments.isEmpty()) return@withLock null

                val first = outOfOrderSegments.first()
                when {
                    first.seq == clientNextSeq -> {
                        outOfOrderSegments.removeAt(0)
                        first
                    }
                    isSeqBefore(first.seq, clientNextSeq) -> {
                        // 过期段，检查是否部分有效
                        val overlap = (clientNextSeq - first.seq).toInt()
                        if (overlap < first.data.size) {
                            // 部分数据仍然有效
                            val validData = first.data.copyOfRange(overlap, first.data.size)
                            outOfOrderSegments.removeAt(0)
                            Segment(clientNextSeq, validData, System.currentTimeMillis())
                        } else {
                            // 完全过期
                            outOfOrderSegments.removeAt(0)
                            null
                        }
                    }
                    else -> null  // 有gap，停止
                }
            }

            if (segment != null) {
                val segEnd = (segment.seq + segment.data.size.toLong()) and 0xFFFFFFFFL
                clientNextSeq = segEnd
                Log.d(LOG_TAG, "Delivering buffered segment seq=${segment.seq}, ${segment.data.size} bytes for $key")

                pendingLock.withLock {
                    pending.addLast(segment.data)
                }
                delivered++
            } else {
                break
            }
        }

        if (delivered > 0) {
            tryFlushUpstream()
            Log.d(LOG_TAG, "Delivered $delivered buffered segments for $key")
        }

    }

    // =============== Upstream Establishment ===============
    private suspend fun establishUpstream(ip: IPv4Packet, syn: TCPSegment, domain: String?) = withContext(Dispatchers.IO) {
        try {
            val port = syn.dstPort
            val hostForDial = if (domain != null) {
                Log.d(LOG_TAG, "Using domain: $domain for SOCKS dial")
                domain
            } else {
                Log.d(LOG_TAG, "No domain found, using IP: ${ip.dst}")
                ip.dst.toString()
            }

            val s = if (bypassDirect) {
                Log.d(LOG_TAG, "Direct dial $hostForDial:$port (bypass)")
                val socket = Socket()
                socket.tcpNoDelay = true
                val protectResult = Vpn2SocksService.protectSocket(socket)
                Log.d(LOG_TAG, "Socket protection result: $protectResult")
                socket.connect(java.net.InetSocketAddress(hostForDial, port), 15000)
                socket
            } else {
                Log.d(LOG_TAG, "Dial SOCKS ${socksEndpoint.host}:${socksEndpoint.port} for $hostForDial:$port")
                val socket = SocksClient(socksEndpoint).dial(hostForDial, port)
                socket.tcpNoDelay = true
                Log.d(LOG_TAG, "SOCKS dial completed successfully for $hostForDial:$port")
                socket
            }

            upstream = s
            upstreamWriter = s.getOutputStream()
            upstreamReader = s.getInputStream()

            stateLock.withLock {
                socksPrimed = true
                if (phase != Phase.CLOSED) phase = Phase.SOCKS_PRIMED
            }

            // Flush any pending upstream data (可能来自握手前缓冲)
            tryFlushUpstream()

            // Prime 下游少量数据
            s.soTimeout = 5
            try {
                val avail = upstreamReader?.available() ?: 0
                if (avail > 0) {
                    val buf = ByteArray(kotlin.math.min(2048, avail))
                    val n = upstreamReader!!.read(buf)
                    if (n > 0) {
                        downPrimeLock.withLock { downPrime = buf.copyOf(n) }
                        Log.d(LOG_TAG, "Prime-downstream buffered: $n bytes for $key")
                    }
                }
            } catch (e: Exception) {
                Log.w(LOG_TAG, "Prime read failed: ${e.message}")
            } finally {
                s.soTimeout = 0
            }

            Log.d(LOG_TAG, "SOCKS connected and primed, waiting for client ACK to start downstream pump")

            // 尝试启动下游
            tryStartDownstream(ip, syn)

        } catch (t: Throwable) {
            Log.e(LOG_TAG, "Upstream connect failed for $key: ${t.message}", t)
            closeConnection()
        }
    }

    // Start downstream loop if both handshake and upstream are ready
    private fun tryStartDownstream(ip: IPv4Packet, tcp: TCPSegment) {
        scope.launch {
            val canStart = stateLock.withLock {
                if (downstreamStarted) return@withLock false
                val ready = handshakeAcked && socksPrimed && (phase != Phase.CLOSED)
                if (ready) {
                    downstreamStarted = true
                    if (phase != Phase.CLOSED) phase = Phase.STREAMING
                    true
                } else false
            }

            if (canStart) {
                // 发送 prime 缓冲
                val prime = downPrimeLock.withLock {
                    val p = downPrime
                    downPrime = null
                    p
                }
                if (prime != null && prime.isNotEmpty()) {
                    sendDataToClient(ip, tcp, prime)
                    Log.d(LOG_TAG, "Prime-downstream sent: ${prime.size} bytes")
                }

                downstreamLoop(ip, tcp)
            }
        }
    }

    // =============== Send Data to Client ===============
    private fun sendDataToClient(ip: IPv4Packet, tcp: TCPSegment, data: ByteArray) {
        val mss = (mtu - 40).coerceAtLeast(536)
        var off = 0

        while (off < data.size && !isClosed) {
            val take = kotlin.math.min(mss, data.size - off)
            val payload = data.copyOfRange(off, off + take)

            val pkt = IpBuilders.tcpPayloadFromServer(
                src = ip.dst, dst = ip.src,
                srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                payload = payload,
                seq = serverSeq.toInt(),
                ack = clientNextSeq.toInt(),
                flags = 0x18, // PSH | ACK
                window = 65535
            )
            packetWriter(listOf(pkt), listOf(ConnectionManager.PROTO_IPV4))
            serverSeq = (serverSeq + take.toLong()) and 0xFFFFFFFFL
            off += take
        }
    }

    // =============== Downstream Pump: Server->Client ===============
    private suspend fun downstreamLoop(ip: IPv4Packet, tcp: TCPSegment) = withContext(Dispatchers.IO) {
        val inp = upstreamReader ?: return@withContext
        val buf = ByteArray(32 * 1024)

        delay(50) // 与原逻辑保持一致的小延迟

        try {
            Log.d(LOG_TAG, "Downstream loop started for $key")
            while (!isClosed) {
                val n = try {
                    inp.read(buf)
                } catch (e: java.net.SocketTimeoutException) {
                    continue
                }

                if (n <= 0) {
                    Log.i(LOG_TAG, "Downstream EOF for $key (server done sending)")
                    try {
                        val finAck = IpBuilders.tcpPayloadFromServer(
                            src = ip.dst, dst = ip.src,
                            srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                            payload = ByteArray(0),
                            seq = serverSeq.toInt(),
                            ack = clientNextSeq.toInt(),
                            flags = 0x11, // FIN | ACK
                            window = 65535
                        )
                        packetWriter(listOf(finAck), listOf(ConnectionManager.PROTO_IPV4))
                        Log.d(LOG_TAG, "Sent FIN|ACK to client for $key after downstream EOF")
                    } catch (_: Throwable) {}
                    stateLock.withLock { if (phase != Phase.CLOSED) phase = Phase.HALF_CLOSED_REMOTE }
                    break
                }

                Log.d(LOG_TAG, "Server->Client: $n bytes for $key")
                sendDataToClient(ip, tcp, buf.copyOf(n))
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Downstream loop error: ${e.message}, ${e.javaClass.simpleName}")
        } finally {
            closeConnection()
        }
    }

    // =============== Upstream Write (Client->Server) ===============
    private suspend fun tryFlushUpstream() = withContext(Dispatchers.IO) {
        val out = upstreamWriter ?: return@withContext

        while (true) {
            val chunk = pendingLock.withLock {
                if (pending.isEmpty()) null else pending.removeFirst()
            } ?: break

            try {
                writeLock.withLock {
                    if (isClosed) return@withLock
                    // 小包合并（尽量减少 write/flush 次数）
                    coalescer.offer(chunk) { bytes ->
                        Log.d(LOG_TAG, "Writing ${bytes.size} bytes to upstream")
                        val ok = try {
                            out.write(bytes)
                            out.flush()
                            true
                        } catch (e: Exception) {
                            Log.e(LOG_TAG, "Upstream write failed: ${e.message}")
                            false
                        }
                        if (ok) Log.d(LOG_TAG, "Successfully wrote to upstream")
                        ok
                    }
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Upstream write failed: ${e.message}")
                closeConnection()
                break
            }
        }

        // 将合并器里残余的数据刷出
        try {
            writeLock.withLock {
                coalescer.flush { bytes ->
                    Log.d(LOG_TAG, "Flushing ${bytes.size} bytes to upstream")
                    val ok = try {
                        out.write(bytes)
                        out.flush()
                        true
                    } catch (e: Exception) {
                        Log.e(LOG_TAG, "Upstream flush failed: ${e.message}")
                        false
                    }
                    if (ok) Log.d(LOG_TAG, "Successfully flushed to upstream")
                    ok
                }
            }
        } catch (_: Throwable) {}

        // After all data is flushed, check if we need to shutdown (安全守卫避免 ENOTCONN)
        val shouldShutdown = stateLock.withLock { pendingShutdown && pending.isEmpty() }
        if (shouldShutdown) {
            try {
                val s = upstream
                if (s != null && s.isConnected && !s.isOutputShutdown) {
                    s.shutdownOutput()
                    Log.d(LOG_TAG, "Upstream output shutdown after flushing all data")
                }
            } catch (e: Throwable) {
                Log.w(LOG_TAG, "Shutdown upstream output failed: ${e.message}")
            }
        }
    }

    // Send pure ACK
    private fun sendPureAck(ip: IPv4Packet, tcp: TCPSegment, ackOverride: Int? = null) {
        val ackPacket = IpBuilders.tcpPayloadFromServer(
            src = ip.dst, dst = ip.src,
            srcPort = tcp.dstPort, dstPort = tcp.srcPort,
            payload = ByteArray(0),
            seq = serverSeq.toInt(),
            ack = ackOverride ?: clientNextSeq.toInt(),
            flags = 0x10, // ACK
            window = 65535
        )
        packetWriter(listOf(ackPacket), listOf(ConnectionManager.PROTO_IPV4))
    }

    // =============== Close (idempotent) ===============
    private fun closeConnection() {
        if (!closedOnce.compareAndSet(false, true)) return
        isClosed = true

        scope.launch {
            try {
                // 强制把合并器残余刷出（即便已关闭也尝试一次）
                writeLock.withLock {
                    val out = upstreamWriter
                    if (out != null) {
                        coalescer.flush { bytes ->
                            try {
                                out.write(bytes)
                                out.flush()
                                true
                            } catch (_: Throwable) { false }
                        }
                    }
                }
            } catch (_: Throwable) {}

            try { upstreamReader?.close() } catch (_: Throwable) {}
            try {
                val s = upstream
                if (s != null && s.isConnected && !s.isOutputShutdown) {
                    try { s.shutdownOutput() } catch (_: Throwable) {}
                }
            } catch (_: Throwable) {}
            try { upstreamWriter?.close() } catch (_: Throwable) {}
            try { upstream?.close() } catch (_: Throwable) {}

            upstreamReader = null
            upstreamWriter = null
            upstream = null

            stateLock.withLock { phase = Phase.CLOSED }
        }
        scope.cancel()
    }
}
