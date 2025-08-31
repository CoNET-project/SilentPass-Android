package com.silentPass.vpn.vpn2socks

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.*
import java.util.concurrent.ConcurrentHashMap
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

    private val stats = ConnectionStats()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

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
                            Log.d(LOG_TAG, "Peer supports SACK for $key")
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
        private var lastWriteTime = 0L
        private var consecutiveSmallWrites = 0
        private val lock = Object()

        // 动态Nagle延迟
        private val getNagleDelay: Long
            get() = when {
                consecutiveSmallWrites > 5 -> 5L   // 检测到大量小包，减少延迟
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
                    // 接近MTU限制
                    buffer.size() >= mtu - 40 -> true
                    // 动态Nagle超时
                    buffer.size() > 0 && (now - lastWriteTime) > getNagleDelay -> true
                    // PSH标志或交互数据
                    data.size == 1 || (data.size < 50 && consecutiveSmallWrites > 3) -> true
                    // 累积足够数据
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

    // =============== Out-of-Order Buffer (TreeMap for O(log n) operations) ===============
    private data class Segment(
        val data: ByteArray,
        val timestamp: Long = System.currentTimeMillis(),
        val retransmitCount: Int = 0
    )

    private val outOfOrderLock = Mutex()
    private val outOfOrderSegments = TreeMap<Long, Segment>()
    private var oooBufferSize = 0
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
            Log.d(LOG_TAG, "FIN received before establishment for $key")
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

        Log.d(LOG_TAG, "Sent SYN-ACK with MSS=$MSS and SACK-Permitted=$weSupportSack for $key")
    }

    private suspend fun handleHandshakeAck(ip: IPv4Packet, tcp: TCPSegment) {
        val ackNum = tcp.ack.toLong() and 0xFFFFFFFFL
        if (ackNum == serverSeq) {
            stateLock.withLock {
                handshakeAcked = true
                phase = Phase.HANDSHAKE_ACKED
            }
            Log.d(LOG_TAG, "3-way handshake established for $key (SACK enabled: $peerSupportsSack)")

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
        Log.d(LOG_TAG, "Client->Server (in-order): ${tcp.payload.size} bytes for $key")

        clientNextSeq = segEnd
        // Keep using onAck to throttle upstream write pacing heuristically.
        congestionControl.onAck(tcp.payload.size)

        // Queue data for upstream
        pendingLock.withLock {
            pending.addLast(tcp.payload.copyOf())
        }

        // Try to deliver buffered out-of-order segments
        deliverBufferedSegments()

        // Flush to upstream
        tryFlushUpstream()

        // Send ACK (with delayed-ACK policy)
        sendAckWithSack(ip, tcp)
    }

    private suspend fun handleRetransmission(
        ip: IPv4Packet, tcp: TCPSegment,
        segSeq: Long, segEnd: Long, expect: Long
    ) {
        stats.retransmittedPackets++

        if (isSeqBefore(segEnd, expect)) {
            // Complete duplicate
            Log.d(LOG_TAG, "Duplicate segment seq=$segSeq expect=$expect for $key")
            congestionControl.onDuplicateAck()
            sendAckWithSack(ip, tcp, immediate = true)
        } else {
            // Partial retransmission with new data
            val overlap = (expect - segSeq).toInt()
            val newData = tcp.payload.copyOfRange(overlap, tcp.payload.size)
            Log.d(LOG_TAG, "Partial retrans: ${newData.size} new bytes for $key")

            clientNextSeq = (expect + newData.size) and 0xFFFFFFFFL
            pendingLock.withLock {
                pending.addLast(newData)
            }
            tryFlushUpstream()
            sendAckWithSack(ip, tcp)
        }
    }

    private suspend fun handleOutOfOrderPacket(ip: IPv4Packet, tcp: TCPSegment, segSeq: Long) {
        val gap = segSeq - clientNextSeq

        // 如果gap很小，可能是轻微乱序，等待一小段时间
        if (gap < 3 * MSS) {
            delay(5)
        }
        val maxGap = when {
            congestionControl.getRto() < 500 -> 32768  // 低延迟网络
            congestionControl.getRto() < 1000 -> 65536  // 中等延迟
            else -> 131072  // 高延迟网络
        }

        if (gap > maxGap) {
            Log.w(LOG_TAG, "Dropping far out-of-order segment gap=$gap maxGap=$maxGap")
            stats.droppedPackets++
            sendAckWithSack(ip, tcp, immediate = true)
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
                stats.outOfOrderPackets++

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

    // =============== Delayed ACK with SACK support ===============
    private fun scheduleAckFlush(ip: IPv4Packet, tcp: TCPSegment) {
        if (ackFlushJob?.isActive == true) return
        ackFlushJob = scope.launch {
            delay(DELAYED_ACK_MS)
            emitAck(ip, tcp)
        }
    }

    private fun emitAck(ip: IPv4Packet, tcp: TCPSegment) {
        // Build SACK options if we have out-of-order segments and peer supports SACK
        val tcpOptions = if (peerSupportsSack && outOfOrderSegments.isNotEmpty()) {
            val sackBlocks = generateSackBlocks()
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

        // For out-of-order segments or duplicates, always send immediately with SACK
        val shouldSendImmediate = immediate ||
                (peerSupportsSack && outOfOrderSegments.isNotEmpty())

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
        // Simple receive window autotuning based on pending + OOO buffers
        val pendingBytes = runBlocking { pendingLock.withLock { pending.sumOf { it.size } } }
        val oooBytes = oooBufferSize
        val used = min(MAX_PENDING_BYTES, pendingBytes + oooBytes)
        val free = (MAX_PENDING_BYTES - used).coerceAtLeast(0)
        val win = free.coerceIn(MIN_ADV_WINDOW, MAX_ADV_WINDOW)
        return win
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
        sendAckWithSack(ip, tcp, immediate = true)

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
                    soTimeout = 200  // ensure reader.read() wakes up
                    Vpn2SocksService.protectSocket(this)
                    connect(InetSocketAddress(hostForDial, port), 15000)
                }
            } else {
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
        Log.d(LOG_TAG, "Sent FIN|ACK to client for $key")
    }

    private suspend fun tryFlushUpstream() = withContext(Dispatchers.IO) {
        val writer = upstreamWriter ?: return@withContext

        while (true) {
            val chunk = pendingLock.withLock {
                if (pending.isEmpty()) null else pending.removeFirst()
            } ?: break

            // Check congestion window
            if (!congestionControl.canSend(chunk.size)) {
                // Put back and wait
                pendingLock.withLock {
                    pending.addFirst(chunk)
                }
                delay(congestionControl.getRto() / 10)
                continue
            }

            try {
                writeLock.withLock {
                    if (isClosed) return@withLock

                    val success = writeCoalescer.offer(chunk) { data: ByteArray ->
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

        // Flush any remaining coalesced data
        try {
            writeLock.withLock {
                if (!isClosed) {
                    writeCoalescer.flush { data: ByteArray ->
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

        // Handle shutdown if needed
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
                // Final flush attempt
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

            // Cancel delayed-ACK timer
            try { ackFlushJob?.cancel() } catch (_: Exception) {}

            // Clean up resources
            try { upstreamReader?.close() } catch (_: Exception) {}
            try { upstreamWriter?.close() } catch (_: Exception) {}
            try { upstream?.close() } catch (_: Exception) {}

            upstreamReader = null
            upstreamWriter = null
            upstream = null

            stateLock.withLock { phase = Phase.CLOSED }

            // Clean up tracking maps
            sentTimeMap.clear()
            outOfOrderSegments.clear()
        }

        scope.cancel()
    }
}