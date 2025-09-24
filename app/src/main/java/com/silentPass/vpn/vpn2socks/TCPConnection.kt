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

        // MSS constants for different connection types
        private const val MSS_STANDARD = 1460     // Standard Ethernet
        private const val MSS_SOCKS = 1420        // SOCKS proxy
        private const val MSS_VPN = 1360          // VPN tunnel

        // Multipliers for CWND calculations
        private const val INITIAL_CWND_MULTIPLIER = 10
        private const val MIN_CWND_MULTIPLIER = 2

        // Other constants
        private const val INITIAL_RTO = 1000L  // 1 second
        private const val MIN_RTO = 200L
        private const val MAX_RTO = 60000L
        private const val SACK_PERMITTED = 4
        private const val SACK_OPTION = 5

        @Volatile private var deferredHalfClose = false

        // --- RFC 7323 Window Scale ---
        private const val WSCALE_KIND = 3
        private const val DEFAULT_WND_SCALE = 7

        // Buffering and window limits
        private const val MAX_PENDING_BYTES = 4 * 1024 * 1024
        private const val MIN_ADV_WINDOW = 1024
        private const val MAX_ADV_WINDOW = 4 * 1024 * 1024

        // Delayed ACK timers
        private const val DELAYED_ACK_MS = 25L
        private const val MAX_PENDING_ACKS = 2
    }

	// ---- Log deduplication (noise control) ----
	private val lastLogTs = ConcurrentHashMap<String, Long>()
	private fun shouldLog(key: String, windowMs: Long = 3000L): Boolean {
		val now = System.currentTimeMillis()
		val last = lastLogTs[key]
		if (last != null && now - last < windowMs) return false
			lastLogTs[key] = now
			return true
    }

	private fun tupleKeyForDedup(extra: String): String = getDisplayKey() + "|" + extra


    @Volatile private var mss: Int = calculateOptimalMSS()
    @Volatile private var mssFallbackSteps: Int = 0  // PMTU blackhole mitigation (max 3)

    // 最近一次客户端（下游）写入上游的时间：用于判断是否处于“只上行阶段”（如测速上传）
    @Volatile private var lastClientWriteTs: Long = 0L


    // Dynamic CWND values based on instance MSS
    private val INITIAL_CWND = INITIAL_CWND_MULTIPLIER * mss
    private val MIN_CWND = MIN_CWND_MULTIPLIER * mss

    private fun calculateOptimalMSS(): Int {
        // 1) 基于实际 MTU 的保守基线（IPv4 20 + TCP 20）
        val base = kotlin.math.min(MSS_STANDARD, (mtu - 40).coerceAtLeast(536))

        // 2) 为隧道/封装预留余量（经验 80B），直连不预留
        val headroom = if (bypassDirect) 0 else 80
        val tunneled = (base - headroom).coerceAtLeast(536)

        // 3) 与经验上限取最小（SOCKS/VPN 场景更保守）
        val cap = if (bypassDirect) MSS_STANDARD else kotlin.math.min(MSS_SOCKS, MSS_VPN + 60) // 1420 vs ~1420

        // 4) 夹在 [1200, cap] 区间内（HTTP/2/TLS 初期分片风险小）
        val clamped = tunneled
            .coerceAtMost(cap)
            .coerceAtLeast(if (bypassDirect) 1200 else 1200)

        return clamped
    }

    // 在出现疑似 PMTU 黑洞或重传异常时，逐级把 MSS 再降 40B（最多 3 次）
    private fun maybeLowerMssOnBlackhole(): Boolean {
        if (mssFallbackSteps >= 3) return false

        val old = mss
        val newMss = (old - 40).coerceAtLeast(536)
        if (newMss < old) {
            mss = newMss

            mssFallbackSteps += 1
            Log.w(LOG_TAG, "PMTU blackhole suspected -> lowering MSS to $mss (step=$mssFallbackSteps) for ${getDisplayKey()}")
            
            // 同步缩放拥塞窗口参数
            congestionControl.onMssReduced(old, newMss)
            return true
        }
        return false
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

    // --- Window Scaling state ---
    @Volatile private var wscaleActive = false         // 双端均宣告后为 true
    @Volatile private var ourWndScale = DEFAULT_WND_SCALE
    @Volatile private var clientWndScale = 0           // 客户端在 SYN 中宣告的 WSCALE
    @Volatile private var peerAdvertisedWnd = 65535    // 已按 clientWndScale 放大后的字节窗口
    @Volatile private var lastAckFromClient: Long = 0L // 最近一次客户端 ACK 序号（用于计算未确认字节）


    // =============== Congestion Control ===============
    private inner class CongestionControl {
        @Volatile private var cwnd = this@TCPConnection.INITIAL_CWND  // Use instance value
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
                if (cwnd < ssthresh) {
                    cwnd = min(cwnd + min(ackedBytes, mss * 2), ssthresh)
                } else {
                    cwnd += (mss * ackedBytes * 2) / cwnd
                }
            }
        }

        fun onDuplicateAck() {
            val count = duplicateAckCount.incrementAndGet()
            stats.duplicateAcks++

            if (count == 3L) {
                ssthresh = max(flightSize / 2, this@TCPConnection.MIN_CWND)  // Use instance value
                cwnd = ssthresh + 3 * mss
                Log.d(LOG_TAG, "Fast recovery triggered: ssthresh=$ssthresh, cwnd=$cwnd")
                // 触发 3 重复 ACK：尝试降 MSS 一档
                maybeLowerMssOnBlackhole()
            }
        }

        fun onTimeout() {
            ssthresh = max(cwnd / 2, this@TCPConnection.MIN_CWND)  // Use instance value
            cwnd = this@TCPConnection.MIN_CWND  // Use instance value
            duplicateAckCount.set(0)
            Log.d(LOG_TAG, "Timeout: ssthresh=$ssthresh, cwnd=$cwnd")

            // 超时：更强烈的黑洞信号，降 MSS 一档
            maybeLowerMssOnBlackhole()
        }

        fun canSend(bytes: Int): Boolean = (flightSize + bytes) <= cwnd

        fun onSend(bytes: Int) {
            flightSize += bytes
        }

        fun getRto(): Long = rto


        // 当 MSS 被动下调时，等比例收缩窗口，避免旧窗口在新 MSS 下偏大
        fun onMssReduced(old: Int, now: Int) {
            if (old <= 0 || now <= 0 || old == now) return
            cwnd = max((cwnd.toLong() * now / old).toInt(), this@TCPConnection.MIN_CWND)
            ssthresh = max((ssthresh.toLong() * now / old).toInt(), this@TCPConnection.MIN_CWND)
            Log.d(LOG_TAG, "Rescaled cwnd=$cwnd ssthresh=$ssthresh due to MSS drop $old->$now for ${getDisplayKey()}")
        }
    }

    // Add standard MSS values


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

    // Parse TCP options from SYN: SACK-Permitted & Window Scale
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

                WSCALE_KIND -> { // Window Scale
                    if (i + 2 < optionsLength) {
                        val length = tcp.raw[optionsStart + i + 1].toInt() and 0xFF
                        if (length == 3) {
                            val valShift = tcp.raw[optionsStart + i + 2].toInt() and 0xFF
                            clientWndScale = (valShift.coerceIn(0, 14)) // RFC：0..14
                            Log.d(LOG_TAG, "Peer Window-Scale=$clientWndScale for ${getDisplayKey()}")
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
                    buffer.size() >= mtu - 100 -> true
                    buffer.size() >= 4096 -> true  // Reduced from 16KB
                    pendingWrites.size >= 2 -> true
                    timeSinceLastWrite > 1 && buffer.size() > 0 -> true  // Reduced from 5ms
                    data.size > 1000 -> true
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
    @Volatile private var warmupDone = false

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

    private var quickAckUntilMs: Long = 0L

    fun isClosed(): Boolean = isClosed

    // =============== Main Packet Processing ===============
    fun onTcp(ip: IPv4Packet, tcp: TCPSegment) {
        scope.launch {
            processPacket(ip, tcp)
        }
    }

    init {
        // Log the MSS being used for this connection
        android.util.Log.i(LOG_TAG, "Connection initialized with MSS=$mss for ${getDisplayKey()} (bypassDirect=$bypassDirect")

        // Start health monitoring
        scope.launch {
            monitorConnectionHealth()
        }
    }

    private suspend fun monitorConnectionHealth() {
        // 等待一段时间让连接有机会建立
        delay(5000)

        while (!isClosed) {
            val checkInterval = when (phase) {
                Phase.SYN, Phase.HANDSHAKE_ACKED, Phase.SOCKS_PRIMED -> 3000L  // Less frequent during setup
                Phase.STREAMING -> 5000L  // Normal monitoring during data transfer
                else -> 10000L
            }
            delay(checkInterval)

            if (phase == Phase.STREAMING ||
                phase == Phase.HALF_CLOSED_LOCAL ||
                phase == Phase.HALF_CLOSED_REMOTE) {
                if (!isSocketHealthy() && !isClosed) {
                    Log.w(LOG_TAG, "Socket unhealthy in phase $phase")
                    closeConnection()
                    break
                }
            }

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
            if (shouldLog(tupleKeyForDedup("ALREADY_CLOSED"), 5000L)) Log.d(LOG_TAG, "Connection already closed for ${getDisplayKey()}")
            return
        }

        // RST handling - check if already closing
        if (tcp.isRST) {
            Log.d(LOG_TAG, "RST received for ${getDisplayKey()}")
            if (!isClosed) {
                closeConnection()
            }
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
                updatePeerWindowFromAck(tcp) // 同步对端窗口与最近ACK
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

    private fun updatePeerWindowFromAck(tcp: TCPSegment) {
        lastAckFromClient = tcp.ack.toLong() and 0xFFFFFFFFL
        // TCP 头 14..15 字节为 16-bit 的 window 字段
        if (tcp.raw.size >= 16) {
            val rawWin = ((tcp.raw[14].toInt() and 0xFF) shl 8) or (tcp.raw[15].toInt() and 0xFF)
            val scaled = rawWin shl clientWndScale   // 按对端 WSCALE 放大
            peerAdvertisedWnd = if (scaled > 0) scaled else 0
        } else {
            // 头长度异常时保持上一次窗口，避免崩溃
        }
    }

    private fun calcAdvertisedWindowField(): Int {
        val advBytes = calcAdvertisedWindow() // 真实可用字节数（0..MAX_ADV_WINDOW）
        val shift = if (wscaleActive) ourWndScale else 0
        var field = advBytes ushr shift
        if (field <= 0) field = 1
        if (field > 65535) field = 65535
        return field
    }

    private suspend fun handleSyn(ip: IPv4Packet, tcp: TCPSegment) {
        val domain = dns.lookupDomain(ip.dst)
        resolvedDomain = domain

        clientSeq0 = tcp.seq.toLong() and 0xFFFFFFFFL
        clientNextSeq = (clientSeq0!! + 1L) and 0xFFFFFFFFL

        parseTcpOptions(tcp)
        // 若客户端在 SYN 中提供了 WSCALE，我们就激活窗口缩放并在 SYN-ACK 中宣告
        wscaleActive = true // 你也可以只在 clientWndScale>0 时启用；这里总是回宣告
        if (!wscaleActive) ourWndScale = 0          // 保险：未启用时右移量为 0

        scope.launch { establishUpstream(ip, tcp, domain) }

        // Send SYN-ACK with dynamic MSS (+ Window-Scale if启用)
        val synAck = IpBuilders.tcpSynAckWithOptions(
            src = ip.dst,
            dst = ip.src,
            srcPort = tcp.dstPort,
            dstPort = tcp.srcPort,
            seq = serverSeq.toInt(),
            ack = clientNextSeq.toInt(),
            window = calcAdvertisedWindowField(), // 写入16bit字段（右移 ourWndScale）
            mss = mss,  // Use dynamic mss instead of MSS
            sackPermitted = weSupportSack,
            windowScale = if (wscaleActive) ourWndScale else null
        )

        packetWriter(listOf(synAck), listOf(ConnectionManager.PROTO_IPV4))
        serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL

        android.util.Log.v(LOG_TAG, "Sent SYN-ACK with MSS=$mss and SACK-Permitted=$weSupportSack for ${getDisplayKey()}")
    }

    private suspend fun handleHandshakeAck(ip: IPv4Packet, tcp: TCPSegment) {
        val ackNum = tcp.ack.toLong() and 0xFFFFFFFFL
        if (ackNum == serverSeq) {
            stateLock.withLock {
                handshakeAcked = true
                phase = Phase.HANDSHAKE_ACKED
            }
            android.util.Log.i(LOG_TAG, "3-way handshake established for ${getDisplayKey()} (SACK enabled: $peerSupportsSack)")

            // 在握手完成后的短时窗口内优先快速 ACK，帮对端更快拉大 cwnd
            quickAckUntilMs = System.currentTimeMillis() + 1500

            // 初始化对端通告窗口（SYN 之后的第一个 ACK 的窗口字段开始生效）
            updatePeerWindowFromAck(tcp)
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
        LogNoiseLimiter.log(LOG_TAG, "cs:${getDisplayKey()}", 'V', 900) {
            "Client->Server (in-order): ${tcp.payload.size} bytes for ${getDisplayKey()}"
        }


        clientNextSeq = segEnd
        congestionControl.onAck(tcp.payload.size)

        // Queue data for upstream
        val payloadCopy = tcp.payload.copyOf()
        pendingLock.withLock {
            pending.addLast(payloadCopy)
            pendingSize.addAndGet(payloadCopy.size)  // 更新大小
        }
        lastClientWriteTs = System.currentTimeMillis()
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
            if (shouldLog(tupleKeyForDedup("DUP_SEG")))
                LogNoiseLimiter.log(LOG_TAG, "dup:${getDisplayKey()}", 'V', 1500) {
                    "Duplicate segment seq=$segSeq expect=$expect for ${getDisplayKey()}"
                }
            congestionControl.onDuplicateAck()
            sendAckWithSack(ip, tcp, immediate = true)
        } else {
            val overlap = (expect - segSeq).toInt()
            val newData = tcp.payload.copyOfRange(overlap, tcp.payload.size)

            LogNoiseLimiter.log(LOG_TAG, "retran:${getDisplayKey()}", 'V', 1500) {
                "Partial retrans: ${newData.size} new bytes for ${getDisplayKey()}"
            }



            clientNextSeq = (expect + newData.size) and 0xFFFFFFFFL
            pendingLock.withLock {
                pending.addLast(newData)
                pendingSize.addAndGet(newData.size)  // 更新大小
            }
            lastClientWriteTs = System.currentTimeMillis()
            tryFlushUpstream()
            sendAckWithSack(ip, tcp)
        }
    }



    private suspend fun handleOutOfOrderPacket(ip: IPv4Packet, tcp: TCPSegment, segSeq: Long) {
        val gap = segSeq - clientNextSeq
        val segEnd = (segSeq + tcp.payload.size) and 0xFFFFFFFFL

        // Small gap - wait briefly
        if (gap <= mss) {  // Changed MSS to mss

            if (segSeq == clientNextSeq) {
                handleInOrderPacket(ip, tcp, segEnd)
                return
            }
        }

        // For small gaps, buffer immediately without delay
        if (gap <= 3 * mss) {
            val newSegment = Segment(
                tcp.payload.copyOf(),
                timestamp = System.currentTimeMillis()
            )

            if (outOfOrderSegments.putIfAbsent(segSeq, newSegment) == null) {
                oooBufferSize.addAndGet(tcp.payload.size)
                stats.outOfOrderPackets++
            }

            // Try immediate delivery
            deliverBufferedSegments()
            sendAckWithSack(ip, tcp, immediate = true)
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
        val toDeliver = mutableListOf<ByteArray>()

        while (outOfOrderSegments.isNotEmpty()) {
            val entry = outOfOrderSegments.firstEntry() ?: break

            if (entry.key == clientNextSeq) {
                // Remove and prepare for delivery
                if (outOfOrderSegments.remove(entry.key, entry.value)) {
                    oooBufferSize.addAndGet(-entry.value.data.size)
                    val segEnd = (entry.key + entry.value.data.size.toLong()) and 0xFFFFFFFFL
                    clientNextSeq = segEnd
                    toDeliver.add(entry.value.data)
                    delivered++
                }
            } else if (isSeqBefore(entry.key, clientNextSeq)) {
                // Handle overlap
                val overlap = (clientNextSeq - entry.key).toInt()
                if (overlap < entry.value.data.size) {
                    val newData = entry.value.data.copyOfRange(overlap, entry.value.data.size)
                    clientNextSeq = (clientNextSeq + newData.size.toLong()) and 0xFFFFFFFFL
                    toDeliver.add(newData)
                    delivered++
                }
                outOfOrderSegments.remove(entry.key)
                oooBufferSize.addAndGet(-entry.value.data.size)
            } else {
                break
            }
        }

        // Batch add to pending queue
        if (toDeliver.isNotEmpty()) {
            pendingLock.withLock {
                for (data in toDeliver) {
                    pending.addLast(data)
                    pendingSize.addAndGet(data.size)
                }
            }
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
                if (shouldLog(tupleKeyForDedup("SACK")))
                    LogNoiseLimiter.log(LOG_TAG, "sack:${getDisplayKey()}", 'V', 1500) {
                        "Sending SACK blocks: ${sackBlocks.joinToString()}"
                    }
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
            window = calcAdvertisedWindowField(),
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

        // Quick-ACK 条件：显式要求 / 有乱序要发 SACK / 仍在快速阶段 / 小包（< MSS/2）
        val quickPhase = now < quickAckUntilMs
        val smallPayload = tcp.payload.size < (mss / 2)
        val shouldSendImmediate = immediate || (peerSupportsSack && hasOutOfOrder) || quickPhase || smallPayload



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
        // 注：返回真实字节窗口；写入 TCP 头前会在 calcAdvertisedWindowField() 内按 ourWndScale 右移
        return free.coerceIn(MIN_ADV_WINDOW, MAX_ADV_WINDOW)
    }

    private suspend fun bufferPreHandshakeData(data: ByteArray) {
        preHandshakeLock.withLock {
            if (preHandshakeBuf.size() + data.size <= 32 * 1024) {
                preHandshakeBuf.write(data)
                Log.d(LOG_TAG, "Buffered pre-handshake ${data.size}B for ${getDisplayKey()}")
            }
        }
        // SYN 前期也视为“客户端在写”
        lastClientWriteTs = System.currentTimeMillis()
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
                lastClientWriteTs = System.currentTimeMillis()
                clientNextSeq = (clientNextSeq + data.size) and 0xFFFFFFFFL
                Log.d(LOG_TAG, "Flushed pre-handshake ${data.size}B for ${getDisplayKey()}")
            }
        }
        tryFlushUpstream()
    }

    private suspend fun handleFIN(ip: IPv4Packet, tcp: TCPSegment) {

        // Check if already closing
        if (isClosed || clientHalfClosed) {
            Log.d(LOG_TAG, "FIN received but already closing for ${getDisplayKey()}")
            return
        }

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

            // Soft-wait up to 800ms for control-plane/overlay readiness (avoid blackhole on first flow)
            try {
                if (!OverlayGate.awaitReady(800)) {
                    Log.d(LOG_TAG, "Overlay not ready within 800ms (soft wait); proceeding")
                }
            } catch (_: Throwable) {}

            val port = syn.dstPort
            // Prefer domain; if absent,再尝试一次反查；若仍无且是 Fake IP，拒绝直拨
            val hostForDial = when {
                domain != null -> domain
                else -> {
                    val d2 = dns.lookupDomain(ip.dst)
                    if (d2 != null) d2
                    else {
                        if (dns.isFakeIp(ip.dst)) {
                            Log.w(LOG_TAG, "Refuse dialing fake IP ${ip.dst} without domain mapping")
                            throw IOException("Missing domain for fake IP ${ip.dst}")
                        }
                        ip.dst.toString()
                    }
                }
            }

            Log.d(LOG_TAG, "Establishing upstream to $hostForDial:$port")
            val speedtestLike = isSpeedtestDomain(hostForDial) || port == 8080

            socket = if (bypassDirect) {
                // 直连模式使用池管理
                pooledSocket = true
                SocketPool.acquire().apply {
                    tcpNoDelay = true

                    // 初值无所谓，稍后统一设置
                    soTimeout = 2000

                    Vpn2SocksService.protectSocket(this)
                    connect(InetSocketAddress(hostForDial, port), 15000)
                }
            } else {
                // SOCKS模式不使用池（因为SocksClient内部创建Socket）
                SocksClient(socksEndpoint).dial(hostForDial, port).apply {
                    tcpNoDelay = true
                    soTimeout = 2000
                }
            }


            // 放大缓冲 & 放宽 read 超时（上传起步更稳）
            try {
                socket.keepAlive = true
                socket.receiveBufferSize = 512 * 1024
                socket.sendBufferSize    = 512 * 1024
                // 测速域名放宽读超时，避免“长时间无下行”的上传阶段被误判
                socket.soTimeout         = if (speedtestLike) 20000 else 8000
            } catch (_: Throwable) {}

            upstream = socket
            upstreamWriter = socket.getOutputStream()
            upstreamReader = socket.getInputStream()


            // Only then update phase
            stateLock.withLock {
                socksPrimed = true
                phase = Phase.SOCKS_PRIMED
            }

            android.util.Log.i(LOG_TAG, "Upstream established for ${getDisplayKey()}")

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
    @Volatile private var canWrite = true  // 新增：控制是否允许写入
    private fun isSocketHealthy(): Boolean {
        return try {
            val socket = upstream
            val currentPhase = phase
            if (socket == null) {
                return currentPhase != Phase.STREAMING &&
                    currentPhase != Phase.HALF_CLOSED_LOCAL &&
                    currentPhase != Phase.HALF_CLOSED_REMOTE
            }
            val isConnected = socket.isConnected && !socket.isClosed
            val canReadFromSocket = !socket.isInputShutdown
            // “读优先”：只要还连着且能读，就继续 downstream
            val healthy = isConnected && canReadFromSocket

            if (!healthy) {
                Log.d(LOG_TAG, "Socket state: closed=${socket.isClosed}, " +
                        "connected=${socket.isConnected}, " +
                        "inputShutdown=${socket.isInputShutdown}, " +
                        "outputShutdown=${socket.isOutputShutdown}, healthy=$healthy")
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
        val buffer = ByteArray(64 * 1024)
        var totalRead = 0
        var consecutiveTimeouts = 0
        val maxConsecutiveTimeouts = 30  // Increase from 10 to 30 (60 seconds with 2s timeout)
        var firstResponseSeen = false
        val speedtestLike = isSpeedtestDomain(resolvedDomain)

        try {
            android.util.Log.i(LOG_TAG, "Downstream loop started for ${getDisplayKey()}")

            while (!isClosed && isSocketHealthy()) {
                val n = try {
                    reader.read(buffer)
                } catch (e: SocketTimeoutException) {
                    consecutiveTimeouts++

                    // 首字节看门狗：测速或仍在持续上传时，不触发快速重试
                    val uploadingLikely =
                        (System.currentTimeMillis() - lastClientWriteTs) < 20_000 || pendingSize.get() > 0
                    if (!firstResponseSeen && consecutiveTimeouts >= 2 && !uploadingLikely && !speedtestLike) {
                        Log.w(LOG_TAG, "No server data within ~${consecutiveTimeouts * 2}s on fresh flow; triggering retry for ${getDisplayKey()}")
                        break
                    }

                    if (consecutiveTimeouts > maxConsecutiveTimeouts) {
                        // Only close if we've received some data
                        if (totalRead > 0) {
                            Log.d(LOG_TAG, "Closing after timeouts with $totalRead bytes received")
                            break
                        } else {
                            Log.w(LOG_TAG, "No data received after ${consecutiveTimeouts * 2}s, closing")
                            break
                        }
                    }
                    continue
                } catch (e: IOException) {
                    // Differentiate between expected and unexpected closures
                    if (totalRead > 0) {
                        Log.d(LOG_TAG, "Connection closed after $totalRead bytes: ${e.message}")
                    } else {
                        Log.e(LOG_TAG, "Connection failed with no data: ${e.message}")
                    }
                    break
                }

                consecutiveTimeouts = 0  // Reset on successful read


                if (n <= 0) {
                    delay(100)
                    if (totalRead == 0) {
                        // Give more retries for initial data
                        delay(500)
                        continue
                    }
                    break
                }

                totalRead += n

                if (!firstResponseSeen) firstResponseSeen = true

                LogNoiseLimiter.log(LOG_TAG, "sc:${getDisplayKey()}", 'V', 900) {
                    "Server->Client: $n bytes (total: $totalRead) for ${getDisplayKey()}"
                }




                sendDataToClient(ip, tcp, buffer.copyOf(n))
            }
        } catch (e: CancellationException) {
            // This is expected when connection is closed
            android.util.Log.i(LOG_TAG, "Downstream loop cancelled after $totalRead bytes for ${getDisplayKey()}")
        } catch (e: Exception) {
            // Only log as error if it's unexpected
            if (!isClosed) {
                Log.e(LOG_TAG, "Downstream error after $totalRead bytes: ${e.message}", e)
            } else {
                Log.d(LOG_TAG, "Downstream stopped after $totalRead bytes: ${e.message}")
            }
        } finally {
            // Only log error if no data was received AND connection wasn't intentionally closed
            if (totalRead == 0 && !isClosed) {
                Log.e(LOG_TAG, "Downstream loop exiting with NO DATA for ${getDisplayKey()}")
            } else {
                android.util.Log.i(LOG_TAG, "Downstream loop exiting after $totalRead bytes for ${getDisplayKey()}")
            }

            // Only close if not already closing
            if (!isClosed) {
                closeConnection()
            }
        }
    }

    private object LogNoiseLimiter {
        private data class Entry(var lastTs: Long, var suppressed: Int, var lastMsgHash: Int)
        private val map = java.util.concurrent.ConcurrentHashMap<String, Entry>()
        private fun now() = android.os.SystemClock.uptimeMillis()

        /**
         * Throttled, de-duplicated log.
         * @param key stable key (e.g., "cs:$fiveTuple", "sc:$fiveTuple")
         * @param level 'V','D','I','W','E'
         */
        fun log(tag: String, key: String, level: Char, intervalMs: Long = 800, build: () -> String) {
            val msg = build()
            val h = msg.hashCode()
            val e = map.getOrPut(key) { Entry(0L, 0, 0) }
            val t = now()
            val isSame = e.lastMsgHash == h
            val elapsed = t - e.lastTs
            if (isSame && elapsed < intervalMs) {
                e.suppressed += 1
                return
            }
            val finalMsg = if (e.suppressed > 0) "$msg (suppressed ${e.suppressed} similar)" else msg
            when (level) {
                'V' -> android.util.Log.v(tag, finalMsg)
                'D' -> android.util.Log.d(tag, finalMsg)
                'I' -> android.util.Log.i(tag, finalMsg)
                'W' -> android.util.Log.w(tag, finalMsg)
                else -> android.util.Log.e(tag, finalMsg)
            }
            e.lastTs = t
            e.lastMsgHash = h
            e.suppressed = 0
        }
    }

    private fun sendDataToClient(ip: IPv4Packet, tcp: TCPSegment, data: ByteArray) {
        // 统一使用“实例级”的动态 MSS，而不是重新用 (mtu-40)
        val mssLocal = mss
        var offset = 0



        while (offset < data.size && !isClosed) {
            val chunkSize = min(mssLocal, data.size - offset)

            // Track send time for RTT measurement
            sentTimeMap[serverSeq] = System.currentTimeMillis()

            // 发送前做一个简单的对端窗口检查（可选，防止超窗）
            val unacked = ((serverSeq - lastAckFromClient) and 0xFFFFFFFFL).toInt()
            val allowed = (peerAdvertisedWnd - unacked).coerceAtLeast(0)
            val realChunk = if (allowed in 1 until chunkSize) allowed else chunkSize

            // 直接从源缓冲切片，避免重复拷贝
            val payloadSlice = data.copyOfRange(offset, offset + realChunk)

            val packet = IpBuilders.tcpPayloadFromServer(
                src = ip.dst, dst = ip.src,
                srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                payload = payloadSlice,
                seq = serverSeq.toInt(),
                ack = clientNextSeq.toInt(),
                flags = 0x18, // PSH | ACK
                window = calcAdvertisedWindowField()
            )

            packetWriter(listOf(packet), listOf(ConnectionManager.PROTO_IPV4))

            // 按实际发送的 realChunk 递增序列号
            serverSeq = (serverSeq + realChunk) and 0xFFFFFFFFL
            offset += realChunk
        }
    }

    // —— 简单识别测速域名 ——（面向 Ookla/MLab/自建测速）
    private fun isSpeedtestDomain(host: String?): Boolean {
        if (host == null) return false
        val h = host.lowercase(Locale.ROOT)
        return h.endsWith(".ooklaserver.net")
            || h.contains("speedtest")
            || h.contains("measurementlab")
            || h.contains("mlab-oti")
            || h.contains("mlab-oti.measurement-lab.org")
    }

    private fun sendFinToClient(ip: IPv4Packet, tcp: TCPSegment) {
        val finPacket = IpBuilders.tcpPayloadFromServer(
            src = ip.dst, dst = ip.src,
            srcPort = tcp.dstPort, dstPort = tcp.srcPort,
            payload = ByteArray(0),
            seq = serverSeq.toInt(),
            ack = clientNextSeq.toInt(),
            flags = 0x11, // FIN | ACK
            window = calcAdvertisedWindowField()
        )
        packetWriter(listOf(finPacket), listOf(ConnectionManager.PROTO_IPV4))
        Log.d(LOG_TAG, "Sent FIN|ACK to client for ${getDisplayKey()}")
    }

    private suspend fun tryFlushUpstream() = withContext(Dispatchers.IO) {
        val writer = upstreamWriter ?: return@withContext
        var totalFlushed = 0

        // Enhanced warmup for SOCKS connections — run ONCE only, very short
        if (!warmupDone && totalFlushed == 0 && phase == Phase.SOCKS_PRIMED && !bypassDirect) {
            // 可按需去掉 delay，或保持 5~10ms 的极短预热
            // delay(5)
            warmupDone = true
        }

        while (canWrite && !outputShutdown) {  // 检查写入状态
            if (!isSocketHealthy()) {
                Log.w(LOG_TAG, "Socket unhealthy, stopping flush")
                canWrite = false
                break
            }

            val chunk = pendingLock.withLock {
                if (pending.isEmpty()) null
                else {
                    val data = pending.removeFirst()
                    pendingSize.addAndGet(-data.size)
                    data
                }
            } ?: break

            try {
                writeLock.withLock {
                    // 三重检查
                    if (!canWrite || outputShutdown || !isSocketHealthy()) {
                        pendingLock.withLock {
                            pending.addFirst(chunk)
                            pendingSize.addAndGet(chunk.size)
                        }
                        return@withLock
                    }

                    val success = writeCoalescer.offer(chunk) { data: ByteArray ->
                        try {
                            // 写入前最后检查
                            if (!canWrite || outputShutdown) {
                                return@offer false
                            }

                            writer.write(data)
                            writer.flush()
                            totalFlushed += data.size
                            true
                        } catch (e: IOException) {
                            Log.e(LOG_TAG, "Write failed: ${e.message}")
                            canWrite = false  // 写入失败后禁止后续写入
                            false
                        }
                    }

                    if (!success) {
                        Log.w(LOG_TAG, "Write failed after $totalFlushed bytes")
                        canWrite = false
                        closeConnection()
                        return@withContext
                    }
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Flush error: ${e.message}")
                canWrite = false
                closeConnection()
                return@withContext
            }
        }

        cleanupPendingData()
    }

    @Volatile private var outputShutdown = false  // 标记输出是否已关闭
    private suspend fun cleanupPendingData() {
        try {
            writeLock.withLock {
                // 先检查是否还能写
                if (!canWrite || outputShutdown) {
                    return@withLock
                }

                if (isSocketHealthy() && upstreamWriter != null) {
                    writeCoalescer.flush { data ->
                        try {
                            // 再次检查写入状态
                            if (canWrite && !outputShutdown && isSocketHealthy()) {
                                upstreamWriter?.write(data)
                                upstreamWriter?.flush()
                                true
                            } else {
                                false
                            }
                        } catch (e: Exception) {
                            Log.d(LOG_TAG, "Final flush exception: ${e.message}")
                            canWrite = false  // 出错后禁止写入
                            false
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(LOG_TAG, "Cleanup failed: ${e.message}")
        }

        val shouldDeferHalfClose = stateLock.withLock {
            pendingShutdown && pending.isEmpty() && !outputShutdown
        }
        if (shouldDeferHalfClose) {
            writeLock.withLock {
                // 不主动半关，延迟到服务端 FIN 或最终 closeConnection() 再处理
                deferredHalfClose = true
                canWrite = false
                Log.d(LOG_TAG, "Deferring upstream half-close (client half-closed & no pending)")
            }
        }
    }


    private fun isSeqBefore(seq1: Long, seq2: Long): Boolean {
        val diff = (seq1 - seq2) and 0xFFFFFFFFL
        return diff > 0x80000000L
    }



    fun closeConnection() {
        // Already closing/closed, just return
        if (!closedOnce.compareAndSet(false, true)) {
            Log.d(LOG_TAG, "Connection already closing/closed for ${getDisplayKey()}")
            return
        }

        Log.d(LOG_TAG, "Starting connection close for ${getDisplayKey()}")

        isClosed = true
        canWrite = false  // 立即禁止写入

        // Use cancelChildren instead of cancel to avoid propagating cancellation
        scope.coroutineContext.cancelChildren()

        cleanupScope.launch {
            try {

                // Give coroutines time to handle cancellation gracefully
                delay(100)

                ackFlushJob?.cancelAndJoin()


                // 安全关闭写入流
                writeLock.withLock {
                    kotlin.runCatching {
                        if (!outputShutdown) {
                            upstreamWriter?.flush()
                        }
                        upstreamWriter?.close()
                    }
                }

                kotlin.runCatching { upstreamReader?.close() }

                upstream?.let { socket ->
                    kotlin.runCatching {
                        if (!socket.isClosed) {

                            if (deferredHalfClose && !socket.isOutputShutdown) { socket.shutdownOutput() }

                            if (bypassDirect && socket.isConnected) {
                                SocketPool.release(socket)
                            } else {
                                socket.close()
                            }
                        }
                    }
                }

                // 清理资源...
            } finally {
                cleanupScope.cancel()
            }
        }
    }
}