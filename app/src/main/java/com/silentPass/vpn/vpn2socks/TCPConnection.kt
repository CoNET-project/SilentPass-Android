package com.silentPass.vpn.vpn2socks

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.util.*
import java.util.concurrent.ConcurrentSkipListMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.max
import kotlin.math.min
import kotlin.random.Random

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
        private const val INITIAL_RTO = 1000L  // 1 second
        private const val MIN_RTO = 200L
        private const val MAX_RTO = 60000L
        private const val SACK_PERMITTED = 4
        private const val SACK_OPTION = 5
        private const val WINDOW_SCALE = 7  // 支持最大窗口 65535 * 2^7
    }

    // 统一的MSS定义
    private val MSS = min(1460, mtu - 40)
    private val INITIAL_CWND = 10 * MSS
    private val MIN_CWND = 2 * MSS

    // =============== Connection Statistics ===============
    private data class ConnectionStats(
        var totalPackets: Long = 0,
        var outOfOrderPackets: Long = 0,
        var retransmittedPackets: Long = 0,
        var droppedPackets: Long = 0,
        var ackedPackets: Long = 0,
        var duplicateAcks: Long = 0
    )

    private val stats = ConnectionStats()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // =============== 接收窗口管理 ===============
    private val maxReceiveBuffer = 1024 * 1024  // 1MB
    @Volatile private var receiveBufferUsed = 0

    private fun calculateReceiveWindow(): Int {
        val available = maxReceiveBuffer - receiveBufferUsed
        // 应用窗口缩放
        val scaledWindow = available shr WINDOW_SCALE
        return min(65535, max(MSS, scaledWindow))
    }

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

            if (cwnd < ssthresh) {
                // Slow start
                cwnd = min(cwnd + MSS, ssthresh)
            } else {
                // Congestion avoidance
                cwnd += (MSS * MSS) / cwnd
            }

            stats.ackedPackets++
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
            rto = min(rto * 2, MAX_RTO)  // 指数退避
            Log.d(LOG_TAG, "Timeout: ssthresh=$ssthresh, cwnd=$cwnd, new_rto=$rto")
        }

        fun onFastRetransmit() {
            ssthresh = max(flightSize / 2, MIN_CWND)
            cwnd = ssthresh + 3 * MSS
        }

        fun canSend(bytes: Int): Boolean {
            return flightSize + bytes <= cwnd
        }

        fun onSend(bytes: Int) {
            flightSize += bytes
        }

        fun getRto(): Long = rto
    }

    // =============== 下行发送缓冲区 (用于重传) ===============
    private data class SendSegment(
        val data: ByteArray,
        val sentTime: Long,
        var retransmitCount: Int = 0,
        var lastSentTime: Long = System.currentTimeMillis(),
        var retransmitJob: Job? = null
    )

    private val sendBuffer = ConcurrentSkipListMap<Long, SendSegment>()
    private val sendBufferLock = Mutex()

    // =============== SACK Support ===============
    private data class SackBlock(val start: Long, val end: Long)

    private fun generateSackBlocks(): List<SackBlock> {
        val blocks = mutableListOf<SackBlock>()
        var currentStart: Long? = null
        var currentEnd: Long? = null

        outOfOrderSegments.forEach { (seq, segment) ->
            val segEnd = seq + segment.data.size.toLong()

            if (currentStart == null) {
                currentStart = seq
                currentEnd = segEnd
            } else if (seq == currentEnd) {
                // Contiguous segment
                currentEnd = segEnd
            } else {
                // Gap found, save current block
                blocks.add(SackBlock(currentStart!!, currentEnd!!))
                currentStart = seq
                currentEnd = segEnd
            }
        }

        if (currentStart != null) {
            blocks.add(SackBlock(currentStart!!, currentEnd!!))
        }

        return blocks.take(3)  // TCP allows max 3 SACK blocks
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

    // 构建TCP选项（用于SYN-ACK）
    private fun buildSynAckOptions(clientTimestamp: Int? = null): ByteArray {
        val options = ByteArrayOutputStream()

        // MSS选项
        options.write(2)
        options.write(4)
        options.write(MSS shr 8)
        options.write(MSS and 0xFF)

        // SACK-Permitted
        options.write(SACK_PERMITTED)
        options.write(2)

        // Window Scale
        options.write(3)
        options.write(3)
        options.write(WINDOW_SCALE)

        // Timestamps选项（如果客户端支持）
        if (clientTimestamp != null) {
            options.write(8)
            options.write(10)
            val timestamp = (System.currentTimeMillis() / 1000).toInt()
            // 写入我们的时间戳
            options.write(timestamp shr 24)
            options.write((timestamp shr 16) and 0xFF)
            options.write((timestamp shr 8) and 0xFF)
            options.write(timestamp and 0xFF)
            // 回显客户端时间戳
            options.write(clientTimestamp shr 24)
            options.write((clientTimestamp shr 16) and 0xFF)
            options.write((clientTimestamp shr 8) and 0xFF)
            options.write(clientTimestamp and 0xFF)
        }

        // NOP填充到4字节边界
        while (options.size() % 4 != 0) {
            options.write(1)  // NOP
        }

        return options.toByteArray()
    }

    // =============== Adaptive Write Coalescer ===============
    private inner class AdaptiveWriteCoalescer {
        private val buffer = ByteArrayOutputStream()
        private var lastWriteTime = 0L
        private var consecutiveSmallWrites = 0
        private val lock = Object()

        private val getNagleDelay: Long
            get() = when {
                consecutiveSmallWrites > 5 -> 5L
                congestionControl.getRto() < 200 -> 10L
                else -> 20L
            }

        fun offer(data: ByteArray, writer: (ByteArray) -> Boolean): Boolean {
            synchronized(lock) {
                if (data.isEmpty()) return true

                if (data.size < 100) consecutiveSmallWrites++
                else consecutiveSmallWrites = 0

                buffer.write(data)
                val now = System.currentTimeMillis()

                val shouldFlush = when {
                    buffer.size() >= mtu - 40 -> true
                    buffer.size() > 0 && (now - lastWriteTime) > getNagleDelay -> true
                    data.size == 1 || (data.size < 50 && consecutiveSmallWrites > 3) -> true
                    buffer.size() > 2048 -> true
                    else -> false
                }

                return if (shouldFlush) {
                    flush(writer)
                } else {
                    lastWriteTime = now
                    true
                }
            }
        }

        fun flush(writer: (ByteArray) -> Boolean): Boolean {
            synchronized(lock) {
                if (buffer.size() == 0) return true

                val data = buffer.toByteArray()
                buffer.reset()
                lastWriteTime = System.currentTimeMillis()

                return writer(data)
            }
        }

        fun hasData(): Boolean = synchronized(lock) { buffer.size() > 0 }
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
    private var serverHighestSent: Long = 0L  // 最高已发送序号

    // =============== Out-of-Order Buffer ===============
    private data class Segment(
        val data: ByteArray,
        val timestamp: Long = System.currentTimeMillis(),
        val retransmitCount: Int = 0
    )

    private val outOfOrderLock = Mutex()
    private val outOfOrderSegments = TreeMap<Long, Segment>()
    private var oooBufferSize = 0
    private val maxOooBufferSize = 256 * 1024

    // =============== Upstream Connection ===============
    private var upstream: Socket? = null
    private var upstreamWriter: java.io.OutputStream? = null
    private var upstreamReader: java.io.InputStream? = null

    // =============== Buffers ===============
    private val pendingLock = Mutex()
    private val pending = ArrayDeque<ByteArray>()
    private val preHandshakeBuf = ByteArrayOutputStream(32 * 1024)
    private val preHandshakeLock = Mutex()

    // =============== Flow Control ===============
    private val congestionControl = CongestionControl()
    private val writeCoalescer = AdaptiveWriteCoalescer()

    // =============== Connection State ===============
    @Volatile private var clientHalfClosed = false
    @Volatile private var pendingShutdown = false
    @Volatile private var downstreamStarted = false
    private val closedOnce = AtomicBoolean(false)

    // RTT测量 - 使用ConcurrentSkipListMap避免内存泄漏
    private val sentTimeMap = ConcurrentSkipListMap<Long, Long>()

    // 客户端重复ACK跟踪（用于快速重传）
    private val dupAckCount = mutableMapOf<Long, Int>()
    private val dupAckLock = Mutex()

    fun isClosed(): Boolean = isClosed

    // =============== Main Packet Processing ===============
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

        // RST handling
        if (tcp.isRST) {
            Log.d(LOG_TAG, "RST received for $key")
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
            // 处理客户端对下行数据的ACK
            if (tcp.isACK) {
                processClientAck(ip, tcp)
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
            Log.d(LOG_TAG, "FIN received before establishment for $key")
            clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
            sendAckWithSack(ip, tcp)
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
        clientSeq0 = tcp.seq.toLong() and 0xFFFFFFFFL
        clientNextSeq = (clientSeq0!! + 1L) and 0xFFFFFFFFL

        scope.launch { establishUpstream(ip, tcp, domain) }

        // 提取客户端时间戳（如果有）
        val clientTimestamp = tcp.extractTimestamp()

        // 发送带选项的SYN-ACK
        val options = buildSynAckOptions(clientTimestamp)

        val synAck = IpBuilders.tcpPayloadFromServer(
            src = ip.dst, dst = ip.src,
            srcPort = tcp.dstPort, dstPort = tcp.srcPort,
            payload = ByteArray(0),
            seq = serverSeq.toInt(),
            ack = clientNextSeq.toInt(),
            flags = 0x12, // SYN | ACK
            window = calculateReceiveWindow(),
            options = options  // 包含MSS、SACK-Permitted、Window Scale等
        )

        packetWriter(listOf(synAck), listOf(ConnectionManager.PROTO_IPV4))
        serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL
        serverHighestSent = serverSeq
    }

    private suspend fun handleHandshakeAck(ip: IPv4Packet, tcp: TCPSegment) {
        val ackNum = tcp.ack.toLong() and 0xFFFFFFFFL
        if (ackNum == serverSeq) {
            stateLock.withLock {
                handshakeAcked = true
                phase = Phase.HANDSHAKE_ACKED
            }
            Log.d(LOG_TAG, "3-way handshake established for $key")

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

    // 处理客户端ACK（包括RTT测量和重传缓冲区管理）
    private suspend fun processClientAck(ip: IPv4Packet, tcp: TCPSegment) {
        val ackNum = tcp.ack.toLong() and 0xFFFFFFFFL

        // RTT测量 - 使用最新确认的段
        val confirmedEntries = sentTimeMap.headMap(ackNum, true)
        confirmedEntries.lastEntry()?.let { entry ->
            val rtt = System.currentTimeMillis() - entry.value
            congestionControl.updateRtt(rtt)
        }
        // 批量清理已确认的时间戳
        confirmedEntries.clear()

        // 清理已确认的发送缓冲区
        sendBufferLock.withLock {
            val confirmedSegments = sendBuffer.headMap(ackNum, false)
            val freedBytes = confirmedSegments.values.sumOf { it.data.size }

            // 取消重传定时器
            confirmedSegments.values.forEach { segment ->
                segment.retransmitJob?.cancel()
            }

            confirmedSegments.clear()

            if (freedBytes > 0) {
                congestionControl.onAck(freedBytes)
            }
        }

        // 检测重复ACK（用于快速重传）
        dupAckLock.withLock {
            if (ackNum < serverHighestSent) {
                val count = dupAckCount.getOrPut(ackNum) { 0 } + 1
                dupAckCount[ackNum] = count

                if (count == 3) {
                    // 触发快速重传
                    triggerFastRetransmit(ackNum, ip, tcp)
                } else if (count > 3) {
                    congestionControl.onDuplicateAck()
                }
            } else {
                // 新的ACK，清理旧的计数
                dupAckCount.clear()
            }
        }
    }

    // 快速重传
    private suspend fun triggerFastRetransmit(ackNum: Long, ip: IPv4Packet, tcp: TCPSegment) {
        Log.d(LOG_TAG, "Fast retransmit triggered after ACK=$ackNum")

        sendBufferLock.withLock {
            // 找到需要重传的段
            sendBuffer.tailMap(ackNum, false).firstEntry()?.let { entry ->
                val seq = entry.key
                val segment = entry.value

                if (segment.retransmitCount < 3) {
                    // 立即重传
                    val packet = IpBuilders.tcpPayloadFromServer(
                        src = ip.dst, dst = ip.src,
                        srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                        payload = segment.data,
                        seq = seq.toInt(),
                        ack = clientNextSeq.toInt(),
                        flags = 0x18, // PSH | ACK
                        window = calculateReceiveWindow()
                    )

                    packetWriter(listOf(packet), listOf(ConnectionManager.PROTO_IPV4))
                    segment.retransmitCount++
                    segment.lastSentTime = System.currentTimeMillis()

                    // 进入快速恢复
                    congestionControl.onFastRetransmit()

                    stats.retransmittedPackets++
                }
            }
        }
    }

    private suspend fun handleEstablishedData(ip: IPv4Packet, tcp: TCPSegment) {
        val segSeq = tcp.seq.toLong() and 0xFFFFFFFFL
        val dataLen = tcp.payload.size.toLong()
        val segEnd = (segSeq + dataLen) and 0xFFFFFFFFL
        val expect = clientNextSeq

        stats.totalPackets++

        // 更新接收缓冲区使用量
        receiveBufferUsed += tcp.payload.size

        when {
            segSeq == expect -> {
                handleInOrderPacket(ip, tcp, segEnd)
            }
            isSeqBefore(segSeq, expect) -> {
                handleRetransmission(ip, tcp, segSeq, segEnd, expect)
            }
            else -> {
                handleOutOfOrderPacket(ip, tcp, segSeq)
            }
        }
    }

    private suspend fun handleInOrderPacket(ip: IPv4Packet, tcp: TCPSegment, segEnd: Long) {
        Log.d(LOG_TAG, "Client->Server (in-order): ${tcp.payload.size} bytes for $key")

        clientNextSeq = segEnd
        congestionControl.onAck(tcp.payload.size)

        pendingLock.withLock {
            pending.addLast(tcp.payload.copyOf())
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
            Log.d(LOG_TAG, "Duplicate segment seq=$segSeq expect=$expect for $key")
            congestionControl.onDuplicateAck()
            sendAckWithSack(ip, tcp)
        } else {
            val overlap = (expect - segSeq).toInt()
            val newData = tcp.payload.copyOfRange(overlap, tcp.payload.size)
            Log.d(LOG_TAG, "Partial retrans: ${newData.size} new bytes for $key")

            clientNextSeq = segEnd
            pendingLock.withLock {
                pending.addLast(newData)
            }
            tryFlushUpstream()
            sendAckWithSack(ip, tcp)
        }
    }

    private suspend fun handleOutOfOrderPacket(ip: IPv4Packet, tcp: TCPSegment, segSeq: Long) {
        val gap = segSeq - clientNextSeq

        if (gap < 3 * MSS) {
            delay(5)
        }

        val maxGap = when {
            congestionControl.getRto() < 500 -> 32768
            congestionControl.getRto() < 1000 -> 65536
            else -> 131072
        }

        if (gap > maxGap) {
            Log.w(LOG_TAG, "Dropping far out-of-order segment gap=$gap maxGap=$maxGap")
            stats.droppedPackets++
            sendAckWithSack(ip, tcp)
            return
        }

        outOfOrderLock.withLock {
            if (oooBufferSize > maxOooBufferSize * 0.8) {
                cleanOldSegments(aggressiveClean = true)
            }

            if (!outOfOrderSegments.containsKey(segSeq)) {
                outOfOrderSegments[segSeq] = Segment(
                    tcp.payload.copyOf(),
                    timestamp = System.currentTimeMillis()
                )
                oooBufferSize += tcp.payload.size

                // 立即发送带SACK的ACK
                sendAckWithSack(ip, tcp, immediate = true)
            }
        }
    }

    private fun cleanOldSegments(aggressiveClean: Boolean = false) {
        val now = System.currentTimeMillis()
        val timeout = if (aggressiveClean) 500L else 1000L

        val expired = outOfOrderSegments.entries.filter {
            now - it.value.timestamp > timeout
        }

        expired.forEach { entry ->
            oooBufferSize -= entry.value.data.size
            outOfOrderSegments.remove(entry.key)
            Log.d(LOG_TAG, "Cleaned expired segment seq=${entry.key}")
        }
    }

    private suspend fun deliverBufferedSegments() {
        var delivered = 0

        outOfOrderLock.withLock {
            while (outOfOrderSegments.isNotEmpty()) {
                val entry = outOfOrderSegments.firstEntry()

                if (entry.key == clientNextSeq) {
                    outOfOrderSegments.pollFirstEntry()
                    oooBufferSize -= entry.value.data.size

                    val segEnd = (entry.key + entry.value.data.size.toLong()) and 0xFFFFFFFFL
                    clientNextSeq = segEnd

                    pendingLock.withLock {
                        pending.addLast(entry.value.data)
                    }

                    delivered++
                    Log.d(LOG_TAG, "Delivered buffered segment seq=${entry.key}, ${entry.value.data.size} bytes")
                } else if (isSeqBefore(entry.key, clientNextSeq)) {
                    val overlap = (clientNextSeq - entry.key).toInt()
                    if (overlap < entry.value.data.size) {
                        val newData = entry.value.data.copyOfRange(overlap, entry.value.data.size)
                        clientNextSeq = (clientNextSeq + newData.size.toLong()) and 0xFFFFFFFFL

                        pendingLock.withLock {
                            pending.addLast(newData)
                        }
                        delivered++
                    }
                    outOfOrderSegments.pollFirstEntry()
                    oooBufferSize -= entry.value.data.size
                } else {
                    break
                }
            }
        }

        if (delivered > 0) {
            Log.d(LOG_TAG, "Delivered $delivered buffered segments for $key")
            tryFlushUpstream()
        }
    }

    private var lastAckTime = 0L
    private var pendingAckCount = 0

    private suspend fun sendAckWithSack(
        ip: IPv4Packet,
        tcp: TCPSegment,
        immediate: Boolean = false
    ) {
        val now = System.currentTimeMillis()

        // 延迟ACK策略
        if (!immediate && (now - lastAckTime < 40) && pendingAckCount < 2) {
            pendingAckCount++
            return
        }

        lastAckTime = now
        pendingAckCount = 0

        // 构建SACK选项（如果有乱序包）
        val options = if (outOfOrderSegments.isNotEmpty()) {
            val sackBlocks = generateSackBlocks()
            if (sackBlocks.isNotEmpty()) {
                Log.d(LOG_TAG, "Sending SACK blocks: ${sackBlocks.joinToString()}")
                buildSackOption(sackBlocks)
            } else {
                ByteArray(0)
            }
        } else {
            ByteArray(0)
        }

        val ackPacket = IpBuilders.tcpPayloadFromServer(
            src = ip.dst, dst = ip.src,
            srcPort = tcp.dstPort, dstPort = tcp.srcPort,
            payload = ByteArray(0),
            seq = serverSeq.toInt(),
            ack = clientNextSeq.toInt(),
            flags = 0x10, // ACK
            window = calculateReceiveWindow(),
            options = options  // 实际包含SACK选项
        )

        packetWriter(listOf(ackPacket), listOf(ConnectionManager.PROTO_IPV4))
    }

    private suspend fun bufferPreHandshakeData(data: ByteArray) {
        preHandshakeLock.withLock {
            if (preHandshakeBuf.size() + data.size <= 32 * 1024) {
                preHandshakeBuf.write(data)
                Log.d(LOG_TAG, "Buffered pre-handshake ${data.size}B for $key")
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
                }
                clientNextSeq = (clientNextSeq + data.size) and 0xFFFFFFFFL
                Log.d(LOG_TAG, "Flushed pre-handshake ${data.size}B for $key")
            }
        }
        tryFlushUpstream()
    }

    private suspend fun handleFIN(ip: IPv4Packet, tcp: TCPSegment) {
        Log.d(LOG_TAG, "FIN received for $key (client half-close)")
        clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
        sendAckWithSack(ip, tcp)

        stateLock.withLock {
            clientHalfClosed = true
            pendingShutdown = true
            phase = Phase.HALF_CLOSED_LOCAL
        }

        tryFlushUpstream()
    }

    private suspend fun establishUpstream(ip: IPv4Packet, syn: TCPSegment, domain: String?) = withContext(Dispatchers.IO) {
        try {
            val port = syn.dstPort
            val hostForDial = domain ?: ip.dst.toString()

            Log.d(LOG_TAG, "Establishing upstream to $hostForDial:$port")

            val socket = if (bypassDirect) {
                Socket().apply {
                    tcpNoDelay = true
                    Vpn2SocksService.protectSocket(this)
                    connect(java.net.InetSocketAddress(hostForDial, port), 15000)
                }
            } else {
                SocksClient(socksEndpoint).dial(hostForDial, port).apply {
                    tcpNoDelay = true
                }
            }

            upstream = socket
            upstreamWriter = socket.getOutputStream()
            upstreamReader = socket.getInputStream()

            stateLock.withLock {
                socksPrimed = true
                phase = Phase.SOCKS_PRIMED
            }

            Log.d(LOG_TAG, "Upstream established for $key")

            tryFlushUpstream()
            tryStartDownstream(ip, syn)

        } catch (e: Exception) {
            Log.e(LOG_TAG, "Upstream establishment failed: ${e.message}", e)
            closeConnection()
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

        try {
            Log.d(LOG_TAG, "Downstream loop started for $key")

            while (!isClosed) {
                val n = try {
                    reader.read(buffer)
                } catch (e: java.net.SocketTimeoutException) {
                    continue
                }

                if (n <= 0) {
                    Log.i(LOG_TAG, "Downstream EOF for $key (server done sending)")
                    sendFinToClient(ip, tcp)
                    stateLock.withLock { phase = Phase.HALF_CLOSED_REMOTE }
                    break
                }

                Log.d(LOG_TAG, "Server->Client: $n bytes for $key")
                sendDataToClient(ip, tcp, buffer.copyOf(n))
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Downstream error: ${e.message}", e)
        } finally {
            closeConnection()
        }
    }

    // 改进的下行数据发送（带重传支持）
    private suspend fun sendDataToClient(ip: IPv4Packet, tcp: TCPSegment, data: ByteArray) {
        var offset = 0

        while (offset < data.size && !isClosed) {
            val chunkSize = min(MSS, data.size - offset)
            val chunk = data.copyOfRange(offset, offset + chunkSize)
            val segSeq = serverSeq

            // 记录发送时间（用于RTT测量）
            sentTimeMap[segSeq] = System.currentTimeMillis()

            // 保存到发送缓冲区（用于重传）
            sendBufferLock.withLock {
                val segment = SendSegment(
                    data = chunk,
                    sentTime = System.currentTimeMillis()
                )
                sendBuffer[segSeq] = segment

                // 启动重传定时器
                segment.retransmitJob = scope.launch {
                    scheduleRetransmission(segSeq, ip, tcp)
                }
            }

            val packet = IpBuilders.tcpPayloadFromServer(
                src = ip.dst, dst = ip.src,
                srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                payload = chunk,
                seq = segSeq.toInt(),
                ack = clientNextSeq.toInt(),
                flags = 0x18, // PSH | ACK
                window = calculateReceiveWindow()
            )

            packetWriter(listOf(packet), listOf(ConnectionManager.PROTO_IPV4))

            serverSeq = (serverSeq + chunkSize) and 0xFFFFFFFFL
            serverHighestSent = serverSeq
            offset += chunkSize

            congestionControl.onSend(chunkSize)
        }
    }

    // 重传调度
    private suspend fun scheduleRetransmission(seq: Long, ip: IPv4Packet, tcp: TCPSegment) {
        delay(congestionControl.getRto())

        sendBufferLock.withLock {
            sendBuffer[seq]?.let { segment ->
                if (segment.retransmitCount < 3) {
                    Log.d(LOG_TAG, "Retransmitting seq=$seq, attempt=${segment.retransmitCount + 1}")

                    val packet = IpBuilders.tcpPayloadFromServer(
                        src = ip.dst, dst = ip.src,
                        srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                        payload = segment.data,
                        seq = seq.toInt(),
                        ack = clientNextSeq.toInt(),
                        flags = 0x18,
                        window = calculateReceiveWindow()
                    )

                    packetWriter(listOf(packet), listOf(ConnectionManager.PROTO_IPV4))

                    segment.retransmitCount++
                    segment.lastSentTime = System.currentTimeMillis()
                    stats.retransmittedPackets++

                    // RTO指数退避
                    congestionControl.onTimeout()

                    // 重新调度
                    segment.retransmitJob = scope.launch {
                        scheduleRetransmission(seq, ip, tcp)
                    }
                } else {
                    Log.w(LOG_TAG, "Max retransmissions reached for seq=$seq")
                }
            }
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
            window = calculateReceiveWindow()
        )
        packetWriter(listOf(finPacket), listOf(ConnectionManager.PROTO_IPV4))
        Log.d(LOG_TAG, "Sent FIN|ACK to client for $key")
    }

    private suspend fun tryFlushUpstream() = withContext(Dispatchers.IO) {
        val writer = upstreamWriter ?: return@withContext

        while (true) {
            val chunk = pendingLock.withLock {
                if (pending.isEmpty()) null else pending.removeFirst()
            } ?: break

            // 更新接收缓冲区
            receiveBufferUsed = max(0, receiveBufferUsed - chunk.size)

            if (!congestionControl.canSend(chunk.size)) {
                pendingLock.withLock {
                    pending.addFirst(chunk)
                }
                delay(congestionControl.getRto() / 10)
                continue
            }

            try {
                writeLock.withLock {
                    if (isClosed) return@withLock

                    val success = writeCoalescer.offer(chunk) { data ->
                        try {
                            Log.d(LOG_TAG, "Flushing ${data.size} bytes to upstream")
                            writer.write(data)
                            writer.flush()
                            congestionControl.onSend(data.size)
                            true
                        } catch (e: Exception) {
                            Log.e(LOG_TAG, "Upstream write failed: ${e.message}")
                            false
                        }
                    }

                    if (!success) {
                        throw Exception("Write failed")
                    }
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Upstream flush error: ${e.message}", e)
                congestionControl.onTimeout()
                closeConnection()
                break
            }
        }

        try {
            writeLock.withLock {
                if (!isClosed) {
                    writeCoalescer.flush { data ->
                        try {
                            Log.d(LOG_TAG, "Final flush ${data.size} bytes to upstream")
                            writer.write(data)
                            writer.flush()
                            true
                        } catch (e: Exception) {
                            false
                        }
                    }
                }
            }
        } catch (_: Exception) {}

        val shouldShutdown = stateLock.withLock {
            pendingShutdown && pending.isEmpty()
        }

        if (shouldShutdown) {
            try {
                upstream?.shutdownOutput()
                Log.d(LOG_TAG, "Upstream output shutdown after flushing all data")
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

        scope.launch {
            try {
                writeLock.withLock {
                    if (!isClosed && upstreamWriter != null) {
                        writeCoalescer.flush { data ->
                            try {
                                upstreamWriter?.write(data)
                                upstreamWriter?.flush()
                                true
                            } catch (_: Exception) {
                                false
                            }
                        }
                    }
                }
            } catch (_: Exception) {}

            // 取消所有重传定时器
            sendBufferLock.withLock {
                sendBuffer.values.forEach { it.retransmitJob?.cancel() }
                sendBuffer.clear()
            }

            try { upstreamReader?.close() } catch (_: Exception) {}
            try { upstreamWriter?.close() } catch (_: Exception) {}
            try { upstream?.close() } catch (_: Exception) {}

            upstreamReader = null
            upstreamWriter = null
            upstream = null

            stateLock.withLock { phase = Phase.CLOSED }

            sentTimeMap.clear()
            outOfOrderSegments.clear()
            dupAckCount.clear()
        }

        scope.cancel()
    }
}

// 扩展函数：从TCP段提取时间戳选项
private fun TCPSegment.extractTimestamp(): Int? {
    // 这需要在TCPSegment类中实现选项解析
    // 这里仅作为示例
    return null
}