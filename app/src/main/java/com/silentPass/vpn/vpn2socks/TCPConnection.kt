package com.silentPass.vpn.vpn2socks

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentSkipListMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.max
import kotlin.math.min
import kotlin.random.Random
import java.util.concurrent.atomic.AtomicInteger


class TCPConnection(
    private val key: String,
    private val mtu: Int,
    private val packetWriter: (List<ByteArray>, List<Int>) -> Unit,
    private val dns: DNSInterceptor,
    private val socksEndpoint: SocksEndpoint,
    private val bypassDirect: Boolean
) {
    companion object {
        private const val LOG_TAG = "TCPConnection"
        private const val MSS = 1460  // Maximum Segment Size
        private const val INITIAL_CWND = 10 * MSS
        private const val MIN_CWND = 2 * MSS
        private const val INITIAL_RTO = 1000L  // 1 second
        private const val MIN_RTO = 200L
        private const val MAX_RTO = 60000L
        private const val SACK_PERMITTED = 4
        private const val SACK_OPTION = 5

        // New: soft limits for inbound buffering and advertised window.
        private const val MAX_PENDING_BYTES = 256 * 1024
        private const val MIN_ADV_WINDOW = 1024
        private const val MAX_ADV_WINDOW = 65535

        // New: delayed ACK timers
        private const val DELAYED_ACK_MS = 40L
        private const val MAX_PENDING_ACKS = 2
    }

    // =============== Connection Statistics ===============
    private data class ConnectionStats(
        var totalPackets: Long = 0,
        var outOfOrderPackets: Long = 0,
        var retransmittedPackets: Long = 0,
        var droppedPackets: Long = 0,
        var ackedPackets: Long = 0,
        var duplicateAcks: Long = 0
    )

    private var resolvedDomain: String? = null

    private fun getDisplayKey(): String {
        return if (resolvedDomain != null) {
            "$key ($resolvedDomain)"  // Use 'key' directly, not getDisplayKey()
        } else {
            key
        }
    }

    private val stats = ConnectionStats()

    private val pendingSize = AtomicInteger(0)  // 新增：缓存pending的总大小

    // SACK support flag (set during handshake)
    @Volatile private var peerSupportsSack = false
    @Volatile private var weSupportSack = true  // We always support SACK

    // =============== Congestion Control ===============
    private inner class CongestionControl {
        @Volatile private var cwnd = INITIAL_CWND
        @Volatile private var ssthresh = Int.MAX_VALUE
        @Volatile private var flightSize = 0

        // RTT estimation (Jacobson/Karels algorithm)
        @Volatile private var srtt = 0L  // Smoothed RTT
        @Volatile private var rttvar = 0L  // RTT variance
        @Volatile private var rto = INITIAL_RTO  // Retransmission timeout

        private val lastAckTime = AtomicLong(0)
        private val duplicateAckCount = AtomicLong(0)

        fun updateRtt(measuredRtt: Long) {
            if (srtt == 0L) {
                srtt = measuredRtt
                rttvar = measuredRtt / 2
            } else {
                val alpha = 0.125
                val beta = 0.25
                rttvar = ((1 - beta) * rttvar + beta * kotlin.math.abs(srtt - measuredRtt)).toLong()
                srtt = ((1 - alpha) * srtt + alpha * measuredRtt).toLong()
            }
            rto = (srtt + 4 * rttvar).coerceIn(MIN_RTO, MAX_RTO)
        }

        fun onAck(ackedBytes: Int) {
            flightSize = max(0, flightSize - ackedBytes)
            duplicateAckCount.set(0)

            if (ackedBytes > 0) {
                // 增加慢启动阈值
                if (cwnd < ssthresh) {
                    cwnd = min(cwnd + min(ackedBytes, MSS * 2), ssthresh) // 更激进的增长
                } else {
                    // 拥塞避免阶段也可以更激进
                    cwnd += (MSS * ackedBytes * 2) / cwnd  // 2倍增长因子
                }
            }
        }

        fun onDuplicateAck() {
            val count = duplicateAckCount.incrementAndGet()
            stats.duplicateAcks++

            if (count == 3L) {
                // Fast retransmit/recovery
                ssthresh = max(flightSize / 2, MIN_CWND)
                cwnd = ssthresh + 3 * MSS
                Log.d(LOG_TAG, "Fast recovery triggered: ssthresh=$ssthresh, cwnd=$cwnd")
            }
        }

        fun onTimeout() {
            ssthresh = max(cwnd / 2, MIN_CWND)
            cwnd = MIN_CWND
            duplicateAckCount.set(0)
            Log.d(LOG_TAG, "Timeout: ssthresh=$ssthresh, cwnd=$cwnd")
        }

        fun canSend(bytes: Int): Boolean {
            return flightSize + bytes <= cwnd
        }

        fun onSend(bytes: Int) {
            flightSize += bytes
        }

        fun getRto(): Long = rto
    }

    // =============== SACK Support ===============
    private data class SackBlock(val start: Long, val end: Long)

    private val outOfOrderSyncLock = Any()
    private fun generateSackBlocks(): List<SackBlock> {
        val blocks = mutableListOf<SackBlock>()
        var currentStart: Long? = null
        var currentEnd: Long? = null

        // ConcurrentSkipListMap is thread-safe for iteration
        outOfOrderSegments.forEach { (seq, segment) ->
            val segEnd = seq + segment.data.size.toLong()

            if (currentStart == null) {
                currentStart = seq
                currentEnd = segEnd
            } else if (seq == currentEnd) {
                currentEnd = segEnd
            } else {
                blocks.add(SackBlock(currentStart!!, currentEnd!!))
                currentStart = seq
                currentEnd = segEnd
            }
        }

        if (currentStart != null) {
            blocks.add(SackBlock(currentStart!!, currentEnd!!))
        }

        return blocks.take(3)
    }

    private fun buildSackOption(blocks: List<SackBlock>): ByteArray {
        if (blocks.isEmpty()) return ByteArray(0)

        val optionLength = 2 + blocks.size * 8
        val option = ByteArrayOutputStream(optionLength)

        option.write(SACK_OPTION)
        option.write(optionLength)

        blocks.forEach { block ->
            // Write start (4 bytes)
            option.write((block.start shr 24).toInt() and 0xFF)
            option.write((block.start shr 16).toInt() and 0xFF)
            option.write((block.start shr 8).toInt() and 0xFF)
            option.write(block.start.toInt() and 0xFF)

            // Write end (4 bytes)
            option.write((block.end shr 24).toInt() and 0xFF)
            option.write((block.end shr 16).toInt() and 0xFF)
            option.write((block.end shr 8).toInt() and 0xFF)
            option.write(block.end.toInt() and 0xFF)
        }

        return option.toByteArray()
    }

    // Parse TCP options from SYN to check for SACK-Permitted
    private fun parseTcpOptions(tcp: TCPSegment) {
        val dataOffset = (tcp.raw[12].toInt() and 0xF0) shr 4
        val optionsLength = (dataOffset * 4) - 20

        if (optionsLength <= 0) return

        val optionsStart = 20
        var i = 0

        while (i < optionsLength && i + optionsStart < tcp.raw.size) {
            val kind = tcp.raw[optionsStart + i].toInt() and 0xFF

            when (kind) {
                0 -> break  // End of options
                1 -> i++    // NOP
                4 -> {      // SACK-Permitted
                    if (i + 1 < optionsLength) {
                        val length = tcp.raw[optionsStart + i + 1].toInt() and 0xFF
                        if (length == 2) {
                            peerSupportsSack = true
                            Log.d(LOG_TAG, "Peer supports SACK for ${getDisplayKey()}")
                        }
                        i += length
                    } else {
                        i++
                    }
                }
                else -> {
                    // Other options
                    if (i + 1 < optionsLength) {
                        val length = tcp.raw[optionsStart + i + 1].toInt() and 0xFF
                        i += if (length > 0) length else 1
                    } else {
                        i++
                    }
                }
            }
        }
    }



    // =============== Adaptive Write Coalescer ===============
    private inner class AdaptiveWriteCoalescer {
        private val buffer = ByteArrayOutputStream()
        private val pendingWrites = mutableListOf<ByteArray>()
        private var lastWriteTime = 0L
        private var consecutiveSmallWrites = 0
        private val lock = Object()

        fun flush(writer: (ByteArray) -> Boolean): Boolean {
            synchronized(lock) {
                if (buffer.size() == 0) return true

                val data = buffer.toByteArray()
                buffer.reset()
                pendingWrites.clear()
                lastWriteTime = System.currentTimeMillis()

                return writer(data)
            }
        }


        fun offer(data: ByteArray, writer: (ByteArray) -> Boolean): Boolean {
            synchronized(lock) {
                pendingWrites.add(data)
                buffer.write(data)

                val now = System.currentTimeMillis()
                val timeSinceLastWrite = now - lastWriteTime

                // 动态决定是否flush
                val shouldFlush = when {
                    buffer.size() >= mtu - 100 -> true // 接近MTU
                    pendingWrites.size >= 3 -> true // 累积了多个小包
                    timeSinceLastWrite > 10 && buffer.size() > 0 -> true // 超时
                    data.size > 1000 -> true // 大包立即发送
                    else -> false
                }

                return if (shouldFlush) {
                    val merged = buffer.toByteArray()
                    buffer.reset()
                    pendingWrites.clear()
                    lastWriteTime = now

                    if (merged.size < 100) consecutiveSmallWrites++
                    else consecutiveSmallWrites = 0

                    writer(merged)
                } else {
                    lastWriteTime = now
                    true
                }
            }
        }
    }

    // =============== State Management ===============
    private val writeLock = Mutex()
    private val stateLock = Mutex()
    @Volatile private var isClosed = false

    private enum class Phase {
        SYN, HANDSHAKE_ACKED, SOCKS_PRIMED, STREAMING,
        HALF_CLOSED_LOCAL, HALF_CLOSED_REMOTE, CLOSED
    }
    @Volatile private var phase: Phase = Phase.SYN
    @Volatile private var handshakeAcked = false
    @Volatile private var socksPrimed = false

    // =============== TCP Sequence State ===============
    private var clientSeq0: Long? = null
    private var clientNextSeq: Long = 0L
    private var serverSeq: Long = Random.nextInt(0, Int.MAX_VALUE).toLong()

    // =============== Out-of-Order Buffer (TreeMap for O(log n) operations) ===============
    private data class Segment(
        val data: ByteArray,
        val timestamp: Long = System.currentTimeMillis(),
        val retransmitCount: Int = 0
    )

    private val outOfOrderLock = Mutex()
    private val outOfOrderSegments = ConcurrentSkipListMap<Long, Segment>()
    private var oooBufferSize = AtomicInteger(0)
    private val maxOooBufferSize = 256 * 1024  // 256KB max

    // =============== Upstream Connection ===============
    private var upstream: Socket? = null
    private var upstreamWriter: java.io.OutputStream? = null
    private var upstreamReader: java.io.InputStream? = null

    // =============== Buffers ===============
    private val pendingLock = Mutex()
    private val pending = ArrayDeque<ByteArray>()
    private val preHandshakeBuf = ByteArrayOutputStream(32 * 1024)
    private val preHandshakeLock = Mutex()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val cleanupScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // =============== Flow Control ===============
    private val congestionControl = CongestionControl()
    private val writeCoalescer = AdaptiveWriteCoalescer()

    // =============== Connection State ===============
    @Volatile private var clientHalfClosed = false
    @Volatile private var pendingShutdown = false
    @Volatile private var downstreamStarted = false
    private val closedOnce = AtomicBoolean(false)

    // Tracking for RTT measurement
    private val sentTimeMap = ConcurrentHashMap<Long, Long>()  // seq -> timestamp

    // New: Delayed-ACK machinery
    @Volatile private var lastAckTime = 0L
    @Volatile private var pendingAckCount = 0
    private var ackFlushJob: Job? = null

    fun isClosed(): Boolean = isClosed

    // =============== Main Packet Processing ===============
    fun onTcp(ip: IPv4Packet, tcp: TCPSegment) {
        scope.launch {
            processPacket(ip, tcp)
        }
    }

    init {
        // 启动健康监测
        scope.launch {
            monitorConnectionHealth()
        }
    }

    private suspend fun monitorConnectionHealth() {
        // 等待一段时间让连接有机会建立
        delay(3000)

        while (!isClosed) {
            delay(1000)

            try {
                // 获取当前状态
                val currentPhase = stateLock.withLock { phase }

                // 根据不同阶段采取不同的健康检查策略
                when (currentPhase) {
                    Phase.SYN, Phase.HANDSHAKE_ACKED, Phase.SOCKS_PRIMED -> {
                        // 建立阶段，不检查 socket 健康状态
                        // 但可以检查是否超时
                        // 这里可以添加建立超时逻辑
                    }

                    Phase.STREAMING, Phase.HALF_CLOSED_LOCAL, Phase.HALF_CLOSED_REMOTE -> {
                        // 数据传输阶段，检查 socket 健康状态
                        if (!isSocketHealthy() && !isClosed) {
                            Log.w(LOG_TAG, "Socket unhealthy in phase $currentPhase for ${getDisplayKey()}")
                            closeConnection()
                            break
                        }
                    }

                    Phase.CLOSED -> {
                        // 已关闭，退出监控
                        break
                    }
                }

                // 监控统计信息
                if (stats.totalPackets > 100) {  // 有足够的样本
                    val packetLoss = stats.droppedPackets.toFloat() / stats.totalPackets
                    if (packetLoss > 0.05) {
                        Log.w(LOG_TAG, "High packet loss: ${(packetLoss * 100).toInt()}% for ${getDisplayKey()}")
                    }
                }

                val rtt = congestionControl.getRto()
                if (rtt > 2000 && currentPhase == Phase.STREAMING) {
                    Log.w(LOG_TAG, "High RTT: ${rtt}ms for ${getDisplayKey()}")
                }

            } catch (e: Exception) {
                Log.e(LOG_TAG, "Health monitor error: ${e.message}")
            }
        }

        Log.d(LOG_TAG, "Health monitor exited for ${getDisplayKey()}")
    }


    private suspend fun processPacket(ip: IPv4Packet, tcp: TCPSegment) {
        if (isClosed) {
            Log.w(LOG_TAG, "Connection already closed for ${getDisplayKey()}")
            return
        }

        // RST handling
        if (tcp.isRST) {
            Log.d(LOG_TAG, "RST received for ${getDisplayKey()}")
            closeConnection()
            return
        }

        // SYN handling
        if (tcp.isSYN && !tcp.isACK) {
            handleSyn(ip, tcp)
            return
        }

        // Handshake completion
        if (!handshakeAcked && tcp.isACK && !tcp.isSYN) {
            handleHandshakeAck(ip, tcp)
            return
        }

        // Established connection
        if (handshakeAcked) {
            // Measure RTT if this is an ACK
            if (tcp.isACK) {
                measureRtt(tcp)
            }

            if (tcp.payload.isNotEmpty()) {
                handleEstablishedData(ip, tcp)
            }
            if (tcp.isFIN) {
                handleFIN(ip, tcp)
            }
            return
        }

        // FIN before establishment
        if (tcp.isFIN) {
            Log.d(LOG_TAG, "FIN received before establishment for ${getDisplayKey()}")
            clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
            sendAckWithSack(ip, tcp, immediate = true)
            closeConnection()
            return
        }

        // Buffer pre-handshake data
        if (tcp.payload.isNotEmpty()) {
            bufferPreHandshakeData(tcp.payload)
        }
    }

    private suspend fun handleSyn(ip: IPv4Packet, tcp: TCPSegment) {
        val domain = dns.lookupDomain(ip.dst)
        resolvedDomain = domain  // Store the domain

        clientSeq0 = tcp.seq.toLong() and 0xFFFFFFFFL
        clientNextSeq = (clientSeq0!! + 1L) and 0xFFFFFFFFL

        // Parse client's TCP options to check for SACK support
        parseTcpOptions(tcp)

        scope.launch { establishUpstream(ip, tcp, domain) }

        // Send SYN-ACK with MSS and SACK-Permitted options
        val synAck = IpBuilders.tcpSynAckWithOptions(
            src = ip.dst,
            dst = ip.src,
            srcPort = tcp.dstPort,
            dstPort = tcp.srcPort,
            seq = serverSeq.toInt(),
            ack = clientNextSeq.toInt(),
            window = calcAdvertisedWindow(),
            mss = MSS,
            sackPermitted = weSupportSack
        )

        packetWriter(listOf(synAck), listOf(ConnectionManager.PROTO_IPV4))
        serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL

        Log.d(LOG_TAG, "Sent SYN-ACK with MSS=$MSS and SACK-Permitted=$weSupportSack for ${getDisplayKey()}")
    }

    private suspend fun handleHandshakeAck(ip: IPv4Packet, tcp: TCPSegment) {
        val ackNum = tcp.ack.toLong() and 0xFFFFFFFFL
        if (ackNum == serverSeq) {
            stateLock.withLock {
                handshakeAcked = true
                phase = Phase.HANDSHAKE_ACKED
            }
            Log.d(LOG_TAG, "3-way handshake established for ${getDisplayKey()} (SACK enabled: $peerSupportsSack)")

            flushPreHandshakeBuffer()
            tryStartDownstream(ip, tcp)

            if (tcp.payload.isNotEmpty()) {
                handleEstablishedData(ip, tcp)
            }
            if (tcp.isFIN) {
                handleFIN(ip, tcp)
            }
        }
    }

    private suspend fun measureRtt(tcp: TCPSegment) {
        val ackSeq = tcp.ack.toLong() and 0xFFFFFFFFL
        sentTimeMap.remove(ackSeq)?.let { sentTime ->
            val rtt = System.currentTimeMillis() - sentTime
            congestionControl.updateRtt(rtt)
        }
    }

    private suspend fun handleEstablishedData(ip: IPv4Packet, tcp: TCPSegment) {
        val segSeq = tcp.seq.toLong() and 0xFFFFFFFFL
        val dataLen = tcp.payload.size.toLong()
        val segEnd = (segSeq + dataLen) and 0xFFFFFFFFL
        val expect = clientNextSeq

        stats.totalPackets++

        when {
            segSeq == expect -> {
                // In-order packet
                handleInOrderPacket(ip, tcp, segEnd)
            }
            isSeqBefore(segSeq, expect) -> {
                // Old segment or partial retransmission
                handleRetransmission(ip, tcp, segSeq, segEnd, expect)
            }
            else -> {
                // Out-of-order packet
                handleOutOfOrderPacket(ip, tcp, segSeq)
            }
        }
    }

    private suspend fun handleInOrderPacket(ip: IPv4Packet, tcp: TCPSegment, segEnd: Long) {
        Log.d(LOG_TAG, "Client->Server (in-order): ${tcp.payload.size} bytes for ${getDisplayKey()}")

        clientNextSeq = segEnd
        congestionControl.onAck(tcp.payload.size)

        // Queue data for upstream
        val payloadCopy = tcp.payload.copyOf()
        pendingLock.withLock {
            pending.addLast(payloadCopy)
            pendingSize.addAndGet(payloadCopy.size)  // 更新大小
        }

        deliverBufferedSegments()
        tryFlushUpstream()
        sendAckWithSack(ip, tcp)
    }

    private suspend fun handleRetransmission(
        ip: IPv4Packet, tcp: TCPSegment,
        segSeq: Long, segEnd: Long, expect: Long
    ) {
        stats.retransmittedPackets++

        if (isSeqBefore(segEnd, expect)) {
            Log.d(LOG_TAG, "Duplicate segment seq=$segSeq expect=$expect for ${getDisplayKey()}")
            congestionControl.onDuplicateAck()
            sendAckWithSack(ip, tcp, immediate = true)
        } else {
            val overlap = (expect - segSeq).toInt()
            val newData = tcp.payload.copyOfRange(overlap, tcp.payload.size)
            Log.d(LOG_TAG, "Partial retrans: ${newData.size} new bytes for ${getDisplayKey()}")

            clientNextSeq = (expect + newData.size) and 0xFFFFFFFFL
            pendingLock.withLock {
                pending.addLast(newData)
                pendingSize.addAndGet(newData.size)  // 更新大小
            }
            tryFlushUpstream()
            sendAckWithSack(ip, tcp)
        }
    }



    private suspend fun handleOutOfOrderPacket(ip: IPv4Packet, tcp: TCPSegment, segSeq: Long) {
        val gap = segSeq - clientNextSeq
        val segEnd = (segSeq + tcp.payload.size) and 0xFFFFFFFFL // 添加这行

        // 小间隙直接等待
        if (gap <= MSS) {
            delay(5)
            // 重新检查是否已经收到
            if (segSeq == clientNextSeq) {
                handleInOrderPacket(ip, tcp, segEnd)
                return
            }
        }

        if (gap < 3 * MSS) {
            // Thread-safe put-if-absent
            val newSegment = Segment(
                tcp.payload.copyOf(),
                timestamp = System.currentTimeMillis()
            )

            if (outOfOrderSegments.putIfAbsent(segSeq, newSegment) == null) {
                oooBufferSize.addAndGet(tcp.payload.size)  // Note: oooBufferSize should be AtomicInteger
                stats.outOfOrderPackets++
            }
            return
        }

        val maxGap = when {
            congestionControl.getRto() < 500 -> 32768
            congestionControl.getRto() < 1000 -> 65536
            else -> 131072
        }

        if (gap > maxGap) {
            Log.w(LOG_TAG, "Dropping far out-of-order segment gap=$gap maxGap=$maxGap")
            stats.droppedPackets++
            sendAckWithSack(ip, tcp, immediate = true)
            return
        }

        // Clean old segments if needed
        if (oooBufferSize.get() > maxOooBufferSize * 0.8) {
            cleanOldSegments(aggressiveClean = true)
        }

        val newSegment = Segment(
            tcp.payload.copyOf(),
            timestamp = System.currentTimeMillis()
        )

        if (outOfOrderSegments.putIfAbsent(segSeq, newSegment) == null) {
            oooBufferSize.addAndGet(tcp.payload.size)
            stats.outOfOrderPackets++
            sendAckWithSack(ip, tcp, immediate = true)
        }
    }

    private fun cleanOldSegments(aggressiveClean: Boolean = false) {
        val now = System.currentTimeMillis()
        val timeout = if (aggressiveClean) 500L else 1000L

        val expired = outOfOrderSegments.entries.filter {
            now - it.value.timestamp > timeout
        }

        expired.forEach { entry ->
            oooBufferSize.addAndGet(-entry.value.data.size)
            outOfOrderSegments.remove(entry.key)
            Log.d(LOG_TAG, "Cleaned expired segment seq=${entry.key}")
        }
    }

    private suspend fun deliverBufferedSegments() {
        var delivered = 0

        while (outOfOrderSegments.isNotEmpty()) {
            val entry = outOfOrderSegments.firstEntry()
            if (entry == null) break

            if (entry.key == clientNextSeq) {
                if (outOfOrderSegments.remove(entry.key, entry.value)) {
                    oooBufferSize.addAndGet(-entry.value.data.size)

                    val segEnd = (entry.key + entry.value.data.size.toLong()) and 0xFFFFFFFFL
                    clientNextSeq = segEnd

                    pendingLock.withLock {
                        pending.addLast(entry.value.data)
                        pendingSize.addAndGet(entry.value.data.size)  // 更新大小
                    }

                    delivered++
                    Log.d(LOG_TAG, "Delivered buffered segment seq=${entry.key}, ${entry.value.data.size} bytes")
                }
            } else if (isSeqBefore(entry.key, clientNextSeq)) {
                val overlap = (clientNextSeq - entry.key).toInt()
                if (overlap < entry.value.data.size) {
                    val newData = entry.value.data.copyOfRange(overlap, entry.value.data.size)
                    clientNextSeq = (clientNextSeq + newData.size.toLong()) and 0xFFFFFFFFL

                    pendingLock.withLock {
                        pending.addLast(newData)
                        pendingSize.addAndGet(newData.size)  // 更新大小
                    }
                    delivered++
                }
                outOfOrderSegments.remove(entry.key)
                oooBufferSize.addAndGet(-entry.value.data.size)
            } else {
                break
            }
        }

        if (delivered > 0) {
            Log.d(LOG_TAG, "Delivered $delivered buffered segments for ${getDisplayKey()}")
            tryFlushUpstream()
        }
    }

    // =============== Delayed ACK with SACK support ===============
    private fun scheduleAckFlush(ip: IPv4Packet, tcp: TCPSegment) {
        ackFlushJob?.cancel()
        ackFlushJob = scope.launch {
            delay(DELAYED_ACK_MS)
            emitAck(ip, tcp)  // This is now a suspend function
        }
    }

    private fun emitAck(ip: IPv4Packet, tcp: TCPSegment) {
        // Build SACK options if we have out-of-order segments and peer supports SACK
        val tcpOptions = if (peerSupportsSack && outOfOrderSegments.isNotEmpty()) {
            val sackBlocks = generateSackBlocks()  // Now properly synchronized
            if (sackBlocks.isNotEmpty()) {
                Log.d(LOG_TAG, "Sending SACK blocks: ${sackBlocks.joinToString()}")
                buildSackOption(sackBlocks)
            } else {
                null
            }
        } else {
            null
        }

        val ackPacket = IpBuilders.tcpPayloadFromServerWithOptions(
            src = ip.dst,
            dst = ip.src,
            srcPort = tcp.dstPort,
            dstPort = tcp.srcPort,
            payload = ByteArray(0),
            seq = serverSeq.toInt(),
            ack = clientNextSeq.toInt(),
            flags = 0x10, // ACK
            window = calcAdvertisedWindow(),
            tcpOptions = tcpOptions
        )

        packetWriter(listOf(ackPacket), listOf(ConnectionManager.PROTO_IPV4))
    }

    private suspend fun sendAckWithSack(
        ip: IPv4Packet,
        tcp: TCPSegment,
        immediate: Boolean = false
    ) {
        val now = System.currentTimeMillis()


        // Check out-of-order segments safely
        val hasOutOfOrder = outOfOrderLock.withLock {
            outOfOrderSegments.isNotEmpty()
        }

        val shouldSendImmediate = immediate ||
                (peerSupportsSack && hasOutOfOrder)


        if (!shouldSendImmediate) {
            if ((now - lastAckTime < DELAYED_ACK_MS) && pendingAckCount < MAX_PENDING_ACKS) {
                pendingAckCount++
                scheduleAckFlush(ip, tcp)
                return
            }
        }

        lastAckTime = now
        pendingAckCount = 0
        emitAck(ip, tcp)
    }

    private fun calcAdvertisedWindow(): Int {
        // 直接使用缓存的大小，避免遍历
        val pendingBytes = pendingSize.get()
        val oooBytes = oooBufferSize.get()
        val used = min(MAX_PENDING_BYTES, pendingBytes + oooBytes)
        val free = (MAX_PENDING_BYTES - used).coerceAtLeast(0)
        return free.coerceIn(MIN_ADV_WINDOW, MAX_ADV_WINDOW)
    }

    private suspend fun bufferPreHandshakeData(data: ByteArray) {
        preHandshakeLock.withLock {
            if (preHandshakeBuf.size() + data.size <= 32 * 1024) {
                preHandshakeBuf.write(data)
                Log.d(LOG_TAG, "Buffered pre-handshake ${data.size}B for ${getDisplayKey()}")
            }
        }
    }

    private suspend fun flushPreHandshakeBuffer() {
        preHandshakeLock.withLock {
            if (preHandshakeBuf.size() > 0) {
                val data = preHandshakeBuf.toByteArray()
                preHandshakeBuf.reset()
                pendingLock.withLock {
                    pending.addLast(data)
                    pendingSize.addAndGet(data.size)  // 更新大小
                }
                clientNextSeq = (clientNextSeq + data.size) and 0xFFFFFFFFL
                Log.d(LOG_TAG, "Flushed pre-handshake ${data.size}B for ${getDisplayKey()}")
            }
        }
        tryFlushUpstream()
    }

    private suspend fun handleFIN(ip: IPv4Packet, tcp: TCPSegment) {
        Log.d(LOG_TAG, "FIN received for ${getDisplayKey()} (client half-close)")
        clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
        sendAckWithSack(ip, tcp, immediate = true)

        stateLock.withLock {
            clientHalfClosed = true
            pendingShutdown = true
            phase = Phase.HALF_CLOSED_LOCAL
        }

        tryFlushUpstream()
    }

    private suspend fun establishUpstream(ip: IPv4Packet, syn: TCPSegment, domain: String?) = withContext(Dispatchers.IO) {
        var socket: Socket? = null
        var pooledSocket = false  // 标记是否从池中获取

        try {
            val port = syn.dstPort
            val hostForDial = domain ?: ip.dst.toString()

            Log.d(LOG_TAG, "Establishing upstream to $hostForDial:$port")

            socket = if (bypassDirect) {
                // 直连模式使用池管理
                pooledSocket = true
                SocketPool.acquire().apply {
                    tcpNoDelay = true
                    soTimeout = 200
                    Vpn2SocksService.protectSocket(this)
                    connect(InetSocketAddress(hostForDial, port), 15000)
                }
            } else {
                // SOCKS模式不使用池（因为SocksClient内部创建Socket）
                SocksClient(socksEndpoint).dial(hostForDial, port).apply {
                    tcpNoDelay = true
                    soTimeout = 200
                }
            }

            upstream = socket
            upstreamWriter = socket.getOutputStream()
            upstreamReader = socket.getInputStream()

            stateLock.withLock {
                socksPrimed = true
                phase = Phase.SOCKS_PRIMED
            }

            Log.d(LOG_TAG, "Upstream established for ${getDisplayKey()}")

            tryFlushUpstream()
            tryStartDownstream(ip, syn)

        } catch (e: Exception) {
            Log.e(LOG_TAG, "Upstream establishment failed: ${e.message}", e)
            closeConnection()
        } finally {
            // 确保异常时释放资源
            if (socket != null && upstream == null) {
                try {
                    if (pooledSocket) {
                        SocketPool.release(socket)
                    } else {
                        socket.close()
                    }
                } catch (e: Exception) {
                    Log.w(LOG_TAG, "Failed to cleanup socket: ${e.message}")
                }
            }
        }
    }

    private fun isSocketHealthy(): Boolean {
        return try {
            val socket = upstream

            if (socket == null) {
                // Socket 还没创建不一定是问题
                val currentPhase = phase  // volatile read
                // 只有在应该有 socket 的阶段才认为是不健康
                return currentPhase == Phase.SYN ||
                        currentPhase == Phase.HANDSHAKE_ACKED ||
                        currentPhase == Phase.SOCKS_PRIMED
            }

            // 检查基本连接状态
            val isConnected = socket.isConnected && !socket.isClosed

            // 检查输入输出状态（半关闭状态也算健康）
            val canRead = !socket.isInputShutdown
            val canWrite = !socket.isOutputShutdown

            // 只要连接还在，且至少能读或写，就认为是健康的
            val healthy = isConnected && (canRead || canWrite)

            if (!healthy) {
                // 详细日志帮助调试
                Log.d(LOG_TAG, "Socket state: closed=${socket.isClosed}, " +
                        "connected=${socket.isConnected}, " +
                        "inputShutdown=${socket.isInputShutdown}, " +
                        "outputShutdown=${socket.isOutputShutdown}, " +
                        "healthy=$healthy (canRead=$canRead, canWrite=$canWrite)")
            }

            healthy
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Error checking socket health: ${e.message}")
            false
        }
    }

    private fun tryStartDownstream(ip: IPv4Packet, tcp: TCPSegment) {
        scope.launch {
            val canStart = stateLock.withLock {
                if (!downstreamStarted && handshakeAcked && socksPrimed) {
                    downstreamStarted = true
                    phase = Phase.STREAMING
                    true
                } else false
            }

            if (canStart) {
                downstreamLoop(ip, tcp)
            }
        }
    }

    private suspend fun downstreamLoop(ip: IPv4Packet, tcp: TCPSegment) = withContext(Dispatchers.IO) {
        val reader = upstreamReader ?: return@withContext
        val buffer = ByteArray(32 * 1024)
        var totalRead = 0  // 添加计数器

        try {
            Log.d(LOG_TAG, "Downstream loop started for ${getDisplayKey()}")

            while (!isClosed && isSocketHealthy()) {
                val n = try {
                    reader.read(buffer)
                } catch (e: java.net.SocketTimeoutException) {
                    // 超时是正常的，继续循环
                    continue
                } catch (e: IOException) {
                    Log.e(LOG_TAG, "Read error in downstream: ${e.message} for ${getDisplayKey()}")
                    break
                }

                if (n <= 0) {
                    Log.i(LOG_TAG, "Downstream EOF after reading $totalRead bytes for ${getDisplayKey()}")
                    sendFinToClient(ip, tcp)
                    stateLock.withLock { phase = Phase.HALF_CLOSED_REMOTE }
                    break
                }

                totalRead += n
                Log.d(LOG_TAG, "Server->Client: $n bytes (total: $totalRead) for ${getDisplayKey()}")
                sendDataToClient(ip, tcp, buffer.copyOf(n))
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Downstream error after $totalRead bytes: ${e.message}", e)
        } finally {
            Log.d(LOG_TAG, "Downstream loop exiting after $totalRead bytes for ${getDisplayKey()}")
            closeConnection()
        }
    }

    private fun sendDataToClient(ip: IPv4Packet, tcp: TCPSegment, data: ByteArray) {
        val mss = (mtu - 40).coerceAtLeast(536)
        var offset = 0

        while (offset < data.size && !isClosed) {
            val chunkSize = min(mss, data.size - offset)
            val chunk = data.copyOfRange(offset, offset + chunkSize)

            // Track send time for RTT measurement
            sentTimeMap[serverSeq] = System.currentTimeMillis()

            val packet = IpBuilders.tcpPayloadFromServer(
                src = ip.dst, dst = ip.src,
                srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                payload = chunk,
                seq = serverSeq.toInt(),
                ack = clientNextSeq.toInt(),
                flags = 0x18, // PSH | ACK
                window = calcAdvertisedWindow()
            )

            packetWriter(listOf(packet), listOf(ConnectionManager.PROTO_IPV4))
            serverSeq = (serverSeq + chunkSize) and 0xFFFFFFFFL
            offset += chunkSize
        }
    }

    private fun sendFinToClient(ip: IPv4Packet, tcp: TCPSegment) {
        val finPacket = IpBuilders.tcpPayloadFromServer(
            src = ip.dst, dst = ip.src,
            srcPort = tcp.dstPort, dstPort = tcp.srcPort,
            payload = ByteArray(0),
            seq = serverSeq.toInt(),
            ack = clientNextSeq.toInt(),
            flags = 0x11, // FIN | ACK
            window = calcAdvertisedWindow()
        )
        packetWriter(listOf(finPacket), listOf(ConnectionManager.PROTO_IPV4))
        Log.d(LOG_TAG, "Sent FIN|ACK to client for ${getDisplayKey()}")
    }

    private suspend fun tryFlushUpstream() = withContext(Dispatchers.IO) {
        val writer = upstreamWriter ?: return@withContext
        var totalFlushed = 0  // 添加计数器

        while (true) {
            if (!isSocketHealthy()) {
                Log.w(LOG_TAG, "Socket unhealthy, stopping flush for ${getDisplayKey()}")
                break  // 使用 break 而不是 return
            }

            val chunk = pendingLock.withLock {
                if (pending.isEmpty()) {
                    null
                } else {
                    val data = pending.removeFirst()
                    pendingSize.addAndGet(-data.size)
                    data
                }
            } ?: break  // 没有更多数据，退出循环


            if (!congestionControl.canSend(chunk.size)) {
                pendingLock.withLock {
                    pending.addFirst(chunk)
                    pendingSize.addAndGet(chunk.size)
                }
                delay(congestionControl.getRto() / 10)
                continue
            }

            try {
                writeLock.withLock {
                    if (!isSocketHealthy()) {
                        pendingLock.withLock {
                            pending.addFirst(chunk)
                            pendingSize.addAndGet(chunk.size)
                        }
                        return@withLock
                    }

                    val success = writeCoalescer.offer(chunk) { data: ByteArray ->
                        try {
                            if (!isSocketHealthy()) {
                                Log.w(LOG_TAG, "Socket became unhealthy before write")
                                return@offer false
                            }

                            Log.d(LOG_TAG, "Flushing ${data.size} bytes to upstream for ${getDisplayKey()}")
                            writer.write(data)
                            writer.flush()
                            totalFlushed += data.size
                            Log.d(LOG_TAG, "Successfully flushed, total: $totalFlushed bytes for ${getDisplayKey()}")
                            congestionControl.onSend(data.size)
                            true
                        } catch (e: SocketException) {
                            Log.e(LOG_TAG, "Socket exception during write for ${getDisplayKey()}: ${e.message}")
                            false
                        } catch (e: IOException) {
                            Log.e(LOG_TAG, "IO exception during write for ${getDisplayKey()}: ${e.message}")
                            false
                        }
                    }

                    if (!success) {
                        Log.w(LOG_TAG, "Write failed after $totalFlushed bytes for ${getDisplayKey()}")
                        closeConnection()  // 关闭连接而不是只返回
                        return@withContext
                    }
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Flush error after $totalFlushed bytes: ${e.message}")
                congestionControl.onTimeout()
                closeConnection()
                return@withContext
            }
        }

        // 完成后调用清理
        cleanupPendingData()
    }

    private suspend fun cleanupPendingData() {
        try {
            writeLock.withLock {
                if (isSocketHealthy() && upstreamWriter != null) {
                    writeCoalescer.flush { data ->
                        try {
                            // 使用 helper 方法检查
                            if (isSocketHealthy()) {
                                upstreamWriter?.write(data)
                                upstreamWriter?.flush()
                                true
                            } else {
                                Log.d(LOG_TAG, "Socket unhealthy during final flush")
                                false
                            }
                        } catch (e: Exception) {
                            Log.d(LOG_TAG, "Final flush exception: ${e.message}")
                            false
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(LOG_TAG, "Cleanup failed: ${e.message}")
        }

        val shouldShutdown = stateLock.withLock {
            pendingShutdown && pending.isEmpty()
        }

        if (shouldShutdown && isSocketHealthy()) {
            try {
                upstream?.shutdownOutput()
                Log.d(LOG_TAG, "Upstream output shutdown")
            } catch (e: Exception) {
                Log.w(LOG_TAG, "Shutdown failed: ${e.message}")
            }
        }
    }


    private fun isSeqBefore(seq1: Long, seq2: Long): Boolean {
        val diff = (seq1 - seq2) and 0xFFFFFFFFL
        return diff > 0x80000000L
    }



    private fun closeConnection() {
        if (!closedOnce.compareAndSet(false, true)) return

        isClosed = true

        // 先取消主作用域
        scope.cancel("Connection closed")

        // 使用清理作用域进行资源清理
        cleanupScope.launch {
            try {
                // 取消所有子任务
                ackFlushJob?.cancelAndJoin()

                // 给一点时间让正在进行的操作完成
                delay(50)

                // 关闭流
                kotlin.runCatching {
                    upstreamWriter?.flush()
                    upstreamWriter?.close()
                }
                kotlin.runCatching { upstreamReader?.close() }

                // 处理 socket
                upstream?.let { socket ->
                    kotlin.runCatching {
                        if (!socket.isClosed) {
                            socket.soTimeout = 100

                            // 确保所有数据都已发送
                            try {
                                socket.shutdownOutput()
                            } catch (e: Exception) {
                                // Socket 可能已经关闭
                            }

                            if (bypassDirect && !socket.isInputShutdown && !socket.isOutputShutdown) {
                                SocketPool.release(socket)
                            } else {
                                socket.close()
                            }
                        }
                    }
                }

                // 清理内存
                sentTimeMap.clear()
                outOfOrderSegments.clear()
                pending.clear()
                pendingSize.set(0)
                oooBufferSize.set(0)

            } catch (e: Exception) {
                Log.e(LOG_TAG, "Error during cleanup: ${e.message}")
            } finally {
                upstreamReader = null
                upstreamWriter = null
                upstream = null

                // 最后取消清理作用域自身
                delay(100) // 给一点时间确保日志输出
                cleanupScope.cancel()
            }
        }
    }
}