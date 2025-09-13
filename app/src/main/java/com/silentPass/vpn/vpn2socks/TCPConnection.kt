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


private const val BBR_STARTUP = 0
private const val BBR_DRAIN = 1
private const val BBR_PROBE_BW = 2

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
        private const val MSS_STANDARD = 1460 // Standard Ethernet
        private const val MSS_SOCKS = 1420 // SOCKS proxy
        private const val MSS_VPN = 1360 // VPN tunnel

        // Multipliers for CWND calculations
        private const val INITIAL_CWND_MULTIPLIER = 10
        private const val MIN_CWND_MULTIPLIER = 2

        // Other constants
        private const val INITIAL_RTO = 1000L // 1 second
        private const val MIN_RTO = 200L
        private const val MAX_RTO = 60000L
        private const val SACK_PERMITTED = 4
        private const val SACK_OPTION = 5

        @Volatile
        private var deferredHalfClose = false

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

    fun updateMinRtt(measuredRtt: Long) {
        val now = System.currentTimeMillis()
        if (measuredRtt < minRttMs || now - minRttStamp > 10_000) {
            minRttMs = measuredRtt
            minRttStamp = now
        }
    }

    private fun tupleKeyForDedup(extra: String): String = getDisplayKey() + "|" + extra


    @Volatile
    private var mss: Int = calculateOptimalMSS()
    @Volatile
    private var mssFallbackSteps: Int = 0 // PMTU blackhole mitigation (max 3)

    // 最近一次客户端（下游）写入上游的时间：用于判断是否处于“只上行阶段”（如测速上传）
    @Volatile
    private var lastClientWriteTs: Long = 0L


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
    // 此函数已被弃用，以支持更智能的 PMTUD
    private fun maybeLowerMssOnBlackhole(): Boolean {
        Log.w(
            LOG_TAG, "PMTU blackhole mitigation logic is deprecated. " +
                    "A proper PMTUD implementation is needed."
        )
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
            "$key ($resolvedDomain)"
        } else {
            key
        }
    }

    private var lastSendTime = 0L
    private val pacingLock = Object()

    // 计算是否需要延迟发送（返回需要等待的毫秒数）
    private fun getPacingDelay(bytes: Int): Long {
        if (!congestionControl.bbrEnabled || congestionControl.bwBps <= 0) return 0L

        synchronized(pacingLock) {
            val pacingRate = congestionControl.bwBps * congestionControl.pacingGain
            val intervalMs = (bytes * 1000.0 / pacingRate).toLong()
            val now = System.currentTimeMillis()
            val elapsed = now - lastSendTime

            return if (elapsed < intervalMs) {
                intervalMs - elapsed
            } else {
                lastSendTime = now
                0L
            }
        }
    }

    // 记录发送时间（在实际发送后调用）
    private fun recordSend(bytesSent: Int) {
        synchronized(pacingLock) {
            val intervalMs = (bytesSent * 1000.0 / (congestionControl.bwBps * congestionControl.pacingGain)).toLong()
            lastSendTime = max(lastSendTime + intervalMs, System.currentTimeMillis())
        }
    }

    private val stats = ConnectionStats()

    private val pendingSize = AtomicInteger(0)

    // SACK support flag (set during handshake)
    @Volatile
    private var peerSupportsSack = false
    @Volatile
    private var weSupportSack = true

    // --- Window Scaling state ---
    @Volatile
    private var wscaleActive = false
    @Volatile
    private var ourWndScale = DEFAULT_WND_SCALE
    @Volatile
    private var clientWndScale = 0
    @Volatile
    private var peerAdvertisedWnd = 65535
    @Volatile
    private var lastAckFromClient: Long = 0L


    // =============== Congestion Control ===============
    private inner class CongestionControl {
        @Volatile
        private var cwnd = this@TCPConnection.INITIAL_CWND
        @Volatile
        private var ssthresh = Int.MAX_VALUE
        @Volatile
        private var flightSize = 0

        // RTT estimation (Jacobson/Karels algorithm)
        @Volatile
        private var srtt = 0L
        @Volatile
        private var rttvar = 0L
        @Volatile
        private var rto = INITIAL_RTO

        private val lastAckTime = AtomicLong(0)
        private val duplicateAckCount = AtomicLong(0)

        // ===== BBR-lite state =====
        @Volatile
        var bbrEnabled = true
        @Volatile
        private var mode = BBR_STARTUP

        @Volatile
        var pacingGain = 2.0
        @Volatile
        private var cwndGain = 2.0
        @Volatile
        var bwBps = 10_000.0
        @Volatile
        private var maxBwSeen = 0.0
        @Volatile
        private var minRttMs = 100L
        @Volatile
        private var minRttStamp = 0L
        private var deliveredBytes = 0L
        private var lastAckTs = 0L
        private var probeToggleTs = 0L
        private var probeHigh = true


        // 增强的RTT统计
        @Volatile
        private var minRttNanos = Long.MAX_VALUE
        @Volatile
        private var maxRttMs = 0L
        @Volatile
        private var avgRttMs = 0L
        private var rttSampleCount = 0L
        private var startupNoGrowthCount = 0
        private var startupBeginTime = System.currentTimeMillis()

        fun updateRtt(measuredRtt: Long) {
            // 现有的RTT更新逻辑
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

            // 更新统计数据
            val now = System.currentTimeMillis()
            if (measuredRtt in 1..10_000) {
                // 更新最小RTT（转换为纳秒存储以保持精度）
                val rttNanos = measuredRtt * 1_000_000L
                if (rttNanos < minRttNanos || now - minRttStamp > 10_000) {
                    minRttNanos = rttNanos
                    minRttMs = measuredRtt
                    minRttStamp = now
                }

                // 更新最大和平均RTT
                maxRttMs = max(maxRttMs, measuredRtt)
                rttSampleCount++
                avgRttMs = ((avgRttMs * (rttSampleCount - 1) + measuredRtt) / rttSampleCount)
            }
        }

        // 获取RTT统计信息
        fun getRttStats(): String {
            return "min=${minRttMs}ms, avg=${avgRttMs}ms, max=${maxRttMs}ms, srtt=${srtt}ms"
        }

        init {
            bbrEnabled = true
            Log.w(LOG_TAG, "BBR ENABLED for ${getDisplayKey()}")
        }

        // 添加上下行ACK处理方法
        fun onUpstreamAck(ackedBytes: Int) {
            if (!bbrEnabled || ackedBytes <= 0) return
            // 上行数据被ACK时的处理
            updateBandwidthEstimate(ackedBytes, true)
        }

        fun onDownstreamAck(ackedBytes: Int) {
            if (!bbrEnabled || ackedBytes <= 0) return
            // 下行数据被ACK时的处理（这是主要的BBR逻辑）
            onClientAck(ackedBytes)
            updateBandwidthEstimate(ackedBytes, false)
        }

        private fun updateBandwidthEstimate(ackedBytes: Int, isUpstream: Boolean) {
            val now = System.currentTimeMillis()

            // 添加调试日志
            if (shouldLog("BBR_BW_${if (isUpstream) "UP" else "DOWN"}", 2000L)) {
                val bwKBps = if (bwBps > 0) bwBps / 1024 else 0
                val rtt = if (minRttMs != Long.MAX_VALUE) minRttMs else srtt
                val modeStr = when (mode) {
                    BBR_STARTUP -> "STARTUP"
                    BBR_DRAIN -> "DRAIN"
                    BBR_PROBE_BW -> "PROBE_BW"
                    else -> "UNKNOWN"
                }
                Log.d(
                    LOG_TAG, "BBR ${if (isUpstream) "UP" else "DOWN"}: " +
                            "bw=${bwKBps.toInt()}KB/s, mode=$modeStr, rtt=${rtt}ms, " +
                            "cwnd=${cwnd / 1024}KB for ${getDisplayKey()}"
                )
            }
        }

        fun getBBRStatus(): String {
            val modeStr = when (mode) {
                BBR_STARTUP -> "STARTUP"
                BBR_DRAIN -> "DRAIN"
                BBR_PROBE_BW -> "PROBE_BW"
                else -> "UNKNOWN"
            }
            val bwKBps = if (bwBps > 0.0) bwBps / 1024 else 0.0
            val rtt = if (minRttMs != Long.MAX_VALUE) minRttMs else srtt
            return "mode=$modeStr, bw=${bwKBps.toInt()}KB/s, rtt=${rtt}ms"
        }

        fun onClientAck(ackedBytes: Int) {
            if (ackedBytes <= 0) return
            flightSize = max(0, flightSize - ackedBytes)
            val now = System.currentTimeMillis()
            
            // 确保初始化
            if (lastAckTs == 0L) {
                lastAckTs = now
                deliveredBytes = ackedBytes
                return  // 第一个ACK不计算带宽
            }
            
            deliveredBytes += ackedBytes
            val dt = now - lastAckTs
            
            // 降低采样间隔要求
            if (dt >= 10L) {  // 从 max(10L, min(srtt/4, 100L)) 简化
                val sampleBw = (deliveredBytes * 1000.0) / dt
                
                // 更新带宽估计（避免bwBps变为0）
                if (sampleBw > 0) {
                    bwBps = if (bwBps > 0) max(bwBps * 0.85, sampleBw) else sampleBw
                    maxBwSeen = max(maxBwSeen, sampleBw)
                }
                
                deliveredBytes = 0
                lastAckTs = now
                
                // 修复 STARTUP 退出条件
                when (mode) {
                    BBR_STARTUP -> {
                        // 需要有效的RTT和带宽估计
                        if (minRttMs < 1000L && bwBps > 0) {
                            startupNoGrowthCount++
                            if (startupNoGrowthCount >= 3 || 
                                (now - startupBeginTime) > 2000L) {  // 2秒超时
                                Log.i(LOG_TAG, "BBR: STARTUP -> DRAIN")
                                mode = BBR_DRAIN
                                pacingGain = 0.7
                                cwndGain = 2.0
                            }
                        }
                    }
                    BBR_DRAIN -> {
                        // 将 flight 下降至 ≈BDP 后进入 ProbeBW
                        if (flightSize <= bdpBytes()) {
                            Log.i(LOG_TAG, "BBR: DRAIN -> PROBE_BW for ${getDisplayKey()}")
                            mode = BBR_PROBE_BW
                            pacingGain = 1.0; cwndGain = 2.0
                            probeToggleTs = now
                            probeHigh = true
                        }
                    }
                    else /* BBR_PROBE_BW */ -> {
                        // 每 ~8×srtt 在 1.25/0.75 间摆动，温和探测
                        if (now - probeToggleTs > (srtt.coerceAtLeast(50L) * 8)) {
                            probeHigh = !probeHigh
                            pacingGain = if (probeHigh) 1.25 else 0.75
                            probeToggleTs = now
                        }
                    }
                }
            }

            // BBR 目标窗：BDP × 增益（保底 MIN_CWND，上限 4MB）
            val target = (bdpBytes() * cwndGain).toInt().coerceAtLeast(this@TCPConnection.MIN_CWND)
            cwnd = target.coerceAtMost(MAX_ADV_WINDOW)
        }

        private fun bdpBytes(): Int {
            val rtt = (if (minRttMs == Long.MAX_VALUE) srtt else minRttMs).coerceAtLeast(50L)
            val bw = if (bwBps > 0.0) bwBps
            else (INITIAL_CWND.toDouble() * 1000.0 / rtt)
            val bdp = (bw * rtt / 1000.0).toInt()
            return bdp.coerceAtLeast(4 * mss)
        }

        fun onClassicAck(ackedBytes: Int) {
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

        fun availableBudget(): Int = max(0, cwnd - flightSize)

        fun onDuplicateAck() {
            stats.duplicateAcks++
            if (bbrEnabled) {
                Log.d(LOG_TAG, "BBR: Packet loss detected via dup-ACKs. Transitioning to PROBE_BW")
                mode = BBR_PROBE_BW
                pacingGain = 1.0; cwndGain = 2.0
                probeToggleTs = System.currentTimeMillis()
                probeHigh = true
            } else {
                val count = duplicateAckCount.incrementAndGet()
                if (count == 3L) {
                    ssthresh = max(flightSize / 2, this@TCPConnection.MIN_CWND)
                    cwnd = ssthresh + 3 * mss
                    Log.d(LOG_TAG, "Fast recovery triggered: ssthresh=$ssthresh, cwnd=$cwnd")
                }
            }
        }

        fun onTimeout() {
            if (bbrEnabled) {
                Log.d(LOG_TAG, "BBR: Timeout detected. Resetting state.")
                mode = BBR_STARTUP
                pacingGain = 2.0; cwndGain = 2.0
                maxBwSeen = 0.0
                minRttMs = Long.MAX_VALUE
                minRttStamp = 0L
            } else {
                ssthresh = max(cwnd / 2, this@TCPConnection.MIN_CWND)
                cwnd = this@TCPConnection.MIN_CWND
            }
            duplicateAckCount.set(0)
            Log.d(LOG_TAG, "Timeout: ssthresh=$ssthresh, cwnd=$cwnd")
        }

        fun canSend(bytes: Int): Boolean = (flightSize + bytes) <= cwnd

        fun onSend(bytes: Int) {
            flightSize += bytes
        }

        fun getRto(): Long = rto

        fun onMssReduced(old: Int, now: Int) {
            if (old <= 0 || now <= 0 || old == now) return
            cwnd = max((cwnd.toLong() * now / old).toInt(), this@TCPConnection.MIN_CWND)
            ssthresh = max((ssthresh.toLong() * now / old).toInt(), this@TCPConnection.MIN_CWND)
            Log.d(
                LOG_TAG,
                "Rescaled cwnd=$cwnd ssthresh=$ssthresh due to MSS drop $old->$now for ${getDisplayKey()}"
            )
        }
    }


    // =============== SACK Support ===============
    private data class SackBlock(val start: Long, val end: Long)

    private val outOfOrderSyncLock = Any()
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
            option.write((block.start shr 24).toInt() and 0xFF)
            option.write((block.start shr 16).toInt() and 0xFF)
            option.write((block.start shr 8).toInt() and 0xFF)
            option.write(block.start.toInt() and 0xFF)

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
                0 -> break
                1 -> i++
                4 -> {
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

                WSCALE_KIND -> {
                    if (i + 2 < optionsLength) {
                        val length = tcp.raw[optionsStart + i + 1].toInt() and 0xFF
                        if (length == 3) {
                            val valShift = tcp.raw[optionsStart + i + 2].toInt() and 0xFF
                            clientWndScale = (valShift.coerceIn(0, 14))
                            Log.d(LOG_TAG, "Peer Window-Scale=$clientWndScale for ${getDisplayKey()}")
                        }
                        i += length
                    } else {
                        i++
                    }
                }

                else -> {
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

                val shouldFlush = when {
                    buffer.size() >= mtu - 100 -> true
                    buffer.size() >= 4096 -> true
                    pendingWrites.size >= 2 -> true
                    timeSinceLastWrite > 1 && buffer.size() > 0 -> true
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
    @Volatile
    private var isClosed = false

    private enum class Phase {
        SYN, HANDSHAKE_ACKED, SOCKS_PRIMED, STREAMING,
        HALF_CLOSED_LOCAL, HALF_CLOSED_REMOTE, CLOSED
    }
    @Volatile
    private var phase: Phase = Phase.SYN
    @Volatile
    private var handshakeAcked = false
    @Volatile
    private var socksPrimed = false
    @Volatile
    private var warmupDone = false

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

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val cleanupScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // =============== Flow Control ===============
    private val congestionControl = CongestionControl()
    private val writeCoalescer = AdaptiveWriteCoalescer()

    // =============== Connection State ===============
    @Volatile
    private var clientHalfClosed = false
    @Volatile
    private var pendingShutdown = false
    @Volatile
    private var downstreamStarted = false
    private val closedOnce = AtomicBoolean(false)

    // Tracking for RTT measurement
    private val sentTimeMap = ConcurrentHashMap<Long, Long>()

    // New: Delayed-ACK machinery
    @Volatile
    private var lastAckTime = 0L
    @Volatile
    private var pendingAckCount = 0
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
        android.util.Log.i(
            LOG_TAG,
            "Connection initialized with MSS=$mss for ${getDisplayKey()} (bypassDirect=$bypassDirect"
        )
        scope.launch {
            monitorConnectionHealth()
        }
    }

    private suspend fun monitorConnectionHealth() {
        delay(5000)

        while (!isClosed) {
            val checkInterval = when (phase) {
                Phase.SYN, Phase.HANDSHAKE_ACKED, Phase.SOCKS_PRIMED -> 3000L
                Phase.STREAMING -> 5000L
                else -> 10000L
            }
            delay(checkInterval)

            if (phase == Phase.STREAMING ||
                phase == Phase.HALF_CLOSED_LOCAL ||
                phase == Phase.HALF_CLOSED_REMOTE
            ) {
                if (!isSocketHealthy() && !isClosed) {
                    Log.w(LOG_TAG, "Socket unhealthy in phase $phase")
                    closeConnection()
                    break
                }
            }

            try {
                val currentPhase = stateLock.withLock { phase }

                when (currentPhase) {
                    Phase.SYN, Phase.HANDSHAKE_ACKED, Phase.SOCKS_PRIMED -> {
                    }

                    Phase.STREAMING, Phase.HALF_CLOSED_LOCAL, Phase.HALF_CLOSED_REMOTE -> {
                        if (!isSocketHealthy() && !isClosed) {
                            Log.w(
                                LOG_TAG,
                                "Socket unhealthy in phase $currentPhase for ${getDisplayKey()}"
                            )
                            closeConnection()
                            break
                        }
                    }

                    Phase.CLOSED -> {
                        break
                    }
                }

                if (stats.totalPackets > 100) {
                    val packetLoss = stats.droppedPackets.toFloat() / stats.totalPackets
                    if (packetLoss > 0.05) {
                        Log.w(
                            LOG_TAG,
                            "High packet loss: ${(packetLoss * 100).toInt()}% for ${getDisplayKey()}"
                        )
                    }
                }

                if (congestionControl.bbrEnabled && currentPhase == Phase.STREAMING) {
                    if (shouldLog("BBR_HEALTH_STATUS", 10000L)) {
                        val bbrStatus = congestionControl.getBBRStatus()
                        Log.i(LOG_TAG, "BBR Status: $bbrStatus for ${getDisplayKey()}")
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
            if (shouldLog(tupleKeyForDedup("ALREADY_CLOSED"), 5000L)) Log.d(
                LOG_TAG,
                "Connection already closed for ${getDisplayKey()}"
            )
            return
        }

        if (tcp.isRST) {
            Log.d(LOG_TAG, "RST received for ${getDisplayKey()}")
            if (!isClosed) {
                closeConnection()
            }
            return
        }

        if (tcp.isSYN && !tcp.isACK) {
            handleSyn(ip, tcp)
            return
        }

        if (!handshakeAcked && tcp.isACK && !tcp.isSYN) {
            handleHandshakeAck(ip, tcp)
            return
        }

        if (handshakeAcked) {
            if (tcp.isACK) {
                measureRtt(tcp)
                updatePeerWindowFromAck(tcp)
            }

            if (tcp.payload.isNotEmpty()) {
                handleEstablishedData(ip, tcp)
            }
            if (tcp.isFIN) {
                handleFIN(ip, tcp)
            }
            return
        }

        if (tcp.isFIN) {
            Log.d(LOG_TAG, "FIN received before establishment for ${getDisplayKey()}")
            clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
            sendAckWithSack(ip, tcp, immediate = true)
            closeConnection()
            return
        }

        if (tcp.payload.isNotEmpty()) {
            bufferPreHandshakeData(tcp.payload)
        }
    }


    private fun updatePeerWindowFromAck(tcp: TCPSegment) {
        val prevAck = lastAckFromClient
        val ackNum = tcp.ack.toLong() and 0xFFFFFFFFL
        lastAckFromClient = ackNum

        if (tcp.raw.size >= 16) {
            val rawWin = ((tcp.raw[14].toInt() and 0xFF) shl 8) or (tcp.raw[15].toInt() and 0xFF)
            val scaled = rawWin shl clientWndScale
            peerAdvertisedWnd = if (scaled > 0) scaled else 0
        }

        val delta = ((ackNum - prevAck) and 0xFFFFFFFFL).toInt().coerceIn(0, 512 * 1024)
        if (delta > 0) {
            congestionControl.onDownstreamAck(delta)
        }
    }

    private fun calcAdvertisedWindowField(): Int {
        val advBytes = calcAdvertisedWindow()
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
        wscaleActive = true
        if (!wscaleActive) ourWndScale = 0

        scope.launch { establishUpstream(ip, tcp, domain) }

        val synAck = IpBuilders.tcpSynAckWithOptions(
            src = ip.dst,
            dst = ip.src,
            srcPort = tcp.dstPort,
            dstPort = tcp.srcPort,
            seq = serverSeq.toInt(),
            ack = clientNextSeq.toInt(),
            window = calcAdvertisedWindowField(),
            mss = mss,
            sackPermitted = weSupportSack,
            windowScale = if (wscaleActive) ourWndScale else null
        )

        packetWriter(listOf(synAck), listOf(ConnectionManager.PROTO_IPV4))
        serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL

        android.util.Log.v(
            LOG_TAG,
            "Sent SYN-ACK with MSS=$mss and SACK-Permitted=$weSupportSack for ${getDisplayKey()}"
        )
    }

    private suspend fun handleHandshakeAck(ip: IPv4Packet, tcp: TCPSegment) {
        val ackNum = tcp.ack.toLong() and 0xFFFFFFFFL
        if (ackNum == serverSeq) {
            stateLock.withLock {
                handshakeAcked = true
                phase = Phase.HANDSHAKE_ACKED
            }
            android.util.Log.i(
                LOG_TAG,
                "3-way handshake established for ${getDisplayKey()} (SACK enabled: $peerSupportsSack)"
            )

            quickAckUntilMs = System.currentTimeMillis() + 1500

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
        sentTimeMap.remove(ackSeq)?.let { sentNanoTime ->
            val rttNanos = System.nanoTime() - sentNanoTime
            val rttMillis = rttNanos / 1_000_000L
            
            if (rttMillis in 1..30_000) {
                congestionControl.updateRtt(rttMillis)
                // 确保 BBR 也更新 minRttMs
                congestionControl.updateMinRtt(rttMillis)  // 新增方法
            }
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
        LogNoiseLimiter.log(LOG_TAG, "cs:${getDisplayKey()}", 'V', 900) {
            "Client->Server (in-order): ${tcp.payload.size} bytes for ${getDisplayKey()}"
        }

        clientNextSeq = segEnd

        if (congestionControl.bbrEnabled) {
            congestionControl.onUpstreamAck(tcp.payload.size)
        } else {
            congestionControl.onClassicAck(tcp.payload.size)
        }

        val payloadCopy = tcp.payload.copyOf()
        pendingLock.withLock {
            pending.addLast(payloadCopy)
            pendingSize.addAndGet(payloadCopy.size)
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
                pendingSize.addAndGet(newData.size)
            }
            lastClientWriteTs = System.currentTimeMillis()
            tryFlushUpstream()
            sendAckWithSack(ip, tcp)
        }
    }


    private suspend fun handleOutOfOrderPacket(ip: IPv4Packet, tcp: TCPSegment, segSeq: Long) {
        val gap = segSeq - clientNextSeq
        val segEnd = (segSeq + tcp.payload.size) and 0xFFFFFFFFL

        if (gap <= mss) {
            if (segSeq == clientNextSeq) {
                handleInOrderPacket(ip, tcp, segEnd)
                return
            }
        }

        if (gap <= 3 * mss) {
            val newSegment = Segment(
                tcp.payload.copyOf(),
                timestamp = System.currentTimeMillis()
            )

            if (outOfOrderSegments.putIfAbsent(segSeq, newSegment) == null) {
                oooBufferSize.addAndGet(tcp.payload.size)
                stats.outOfOrderPackets++
            }

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
                if (outOfOrderSegments.remove(entry.key, entry.value)) {
                    oooBufferSize.addAndGet(-entry.value.data.size)
                    val segEnd = (entry.key + entry.value.data.size.toLong()) and 0xFFFFFFFFL
                    clientNextSeq = segEnd
                    toDeliver.add(entry.value.data)
                    delivered++
                }
            } else if (isSeqBefore(entry.key, clientNextSeq)) {
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

    private fun scheduleAckFlush(ip: IPv4Packet, tcp: TCPSegment) {
        ackFlushJob?.cancel()
        ackFlushJob = scope.launch {
            delay(DELAYED_ACK_MS)
            emitAck(ip, tcp)
        }
    }

    private fun emitAck(ip: IPv4Packet, tcp: TCPSegment) {
        val tcpOptions = if (peerSupportsSack && outOfOrderSegments.isNotEmpty()) {
            val sackBlocks = generateSackBlocks()
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
            flags = 0x10,
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

        val hasOutOfOrder = outOfOrderLock.withLock {
            outOfOrderSegments.isNotEmpty()
        }

        val quickPhase = now < quickAckUntilMs
        val smallPayload = tcp.payload.size < (mss / 2)
        val shouldSendImmediate =
            immediate || (peerSupportsSack && hasOutOfOrder) || quickPhase || smallPayload

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
        lastClientWriteTs = System.currentTimeMillis()
    }

    private suspend fun flushPreHandshakeBuffer() {
        preHandshakeLock.withLock {
            if (preHandshakeBuf.size() > 0) {
                val data = preHandshakeBuf.toByteArray()
                preHandshakeBuf.reset()
                pendingLock.withLock {
                    pending.addLast(data)
                    pendingSize.addAndGet(data.size)
                }
                lastClientWriteTs = System.currentTimeMillis()
                clientNextSeq = (clientNextSeq + data.size) and 0xFFFFFFFFL
                Log.d(LOG_TAG, "Flushed pre-handshake ${data.size}B for ${getDisplayKey()}")
            }
        }
        tryFlushUpstream()
    }

    private suspend fun handleFIN(ip: IPv4Packet, tcp: TCPSegment) {
        if (isClosed || clientHalfClosed) {
                Log.d(LOG_TAG, "FIN received but already closing")
                return
            }

            Log.d(LOG_TAG, "FIN received (client half-close)")
            clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
            sendAckWithSack(ip, tcp, immediate = true)

            stateLock.withLock {
                clientHalfClosed = true
                pendingShutdown = true
                phase = Phase.HALF_CLOSED_LOCAL
            }

            // 不要立即关闭！等待数据传输完成
            tryFlushUpstream()
            
            // 延迟关闭，给下行数据时间
            scope.launch {
                delay(1000)  // 等待1秒
                if (pendingSize.get() == 0 && !outputShutdown) {
                    writeLock.withLock {
                        upstream?.shutdownOutput()
                        outputShutdown = true
                    }
                }
            }
    }

    private suspend fun establishUpstream(ip: IPv4Packet, syn: TCPSegment, domain: String?) =
        withContext(Dispatchers.IO) {
            var socket: Socket? = null
            var pooledSocket = false

            try {
                try {
                    if (!OverlayGate.awaitReady(800)) {
                        Log.d(
                            LOG_TAG,
                            "Overlay not ready within 800ms (soft wait); proceeding"
                        )
                    }
                } catch (_: Throwable) {
                }

                val port = syn.dstPort
                val hostForDial = domain ?: ip.dst.toString()

                Log.d(LOG_TAG, "Establishing upstream to $hostForDial:$port")
                val speedtestLike = isSpeedtestDomain(hostForDial) || port == 8080

                socket = if (bypassDirect) {
                    pooledSocket = true
                    SocketPool.acquire().apply {
                        tcpNoDelay = true
                        soTimeout = 2000
                        Vpn2SocksService.protectSocket(this)
                        connect(InetSocketAddress(hostForDial, port), 15000)
                    }
                } else {
                    SocksClient(socksEndpoint).dial(hostForDial, port).apply {
                        tcpNoDelay = true
                        soTimeout = 2000
                    }
                }


                try {
                    socket.keepAlive = true
                    socket.receiveBufferSize = 512 * 1024
                    socket.sendBufferSize = 512 * 1024
                    socket.soTimeout = if (speedtestLike) 20000 else 8000
                } catch (_: Throwable) {
                }

                upstream = socket
                upstreamWriter = socket.getOutputStream()
                upstreamReader = socket.getInputStream()


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

    @Volatile
    private var canWrite = true
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
            val healthy = isConnected && canReadFromSocket

            if (!healthy) {
                Log.d(
                    LOG_TAG, "Socket state: closed=${socket.isClosed}, " +
                            "connected=${socket.isConnected}, " +
                            "inputShutdown=${socket.isInputShutdown}, " +
                            "outputShutdown=${socket.isOutputShutdown}, healthy=$healthy"
                )
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

    private suspend fun downstreamLoop(ip: IPv4Packet, tcp: TCPSegment) =
        withContext(Dispatchers.IO) {
            val reader = upstreamReader ?: return@withContext
            val buffer = ByteArray(64 * 1024)
            var totalRead = 0
            var consecutiveTimeouts = 0
            val maxConsecutiveTimeouts = 30
            var firstResponseSeen = false
            val speedtestLike = isSpeedtestDomain(resolvedDomain)

            try {
                android.util.Log.i(LOG_TAG, "Downstream loop started for ${getDisplayKey()}")

                while (!isClosed && isSocketHealthy()) {
                    val n = try {
                        reader.read(buffer)
                    } catch (e: SocketTimeoutException) {
                        consecutiveTimeouts++

                        val uploadingLikely =
                            (System.currentTimeMillis() - lastClientWriteTs) < 20_000 || pendingSize.get() > 0
                        if (!firstResponseSeen && consecutiveTimeouts >= 2 && !uploadingLikely && !speedtestLike) {
                            Log.w(
                                LOG_TAG,
                                "No server data within ~${consecutiveTimeouts * 2}s on fresh flow; triggering retry for ${getDisplayKey()}"
                            )
                            break
                        }

                        if (consecutiveTimeouts > maxConsecutiveTimeouts) {
                            if (totalRead > 0) {
                                Log.d(
                                    LOG_TAG,
                                    "Closing after timeouts with $totalRead bytes received"
                                )
                                break
                            } else {
                                Log.w(
                                    LOG_TAG,
                                    "No data received after ${consecutiveTimeouts * 2}s, closing"
                                )
                                break
                            }
                        }
                        continue
                    } catch (e: IOException) {
                        if (totalRead > 0) {
                            Log.d(
                                LOG_TAG,
                                "Connection closed after $totalRead bytes: ${e.message}"
                            )
                        } else {
                            Log.e(
                                LOG_TAG,
                                "Connection failed with no data: ${e.message}"
                            )
                        }
                        break
                    }

                    consecutiveTimeouts = 0


                    if (n <= 0) {
                        delay(100)
                        if (totalRead == 0) {
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
                android.util.Log.i(
                    LOG_TAG,
                    "Downstream loop cancelled after $totalRead bytes for ${getDisplayKey()}"
                )
            } catch (e: Exception) {
                if (!isClosed) {
                    Log.e(
                        LOG_TAG,
                        "Downstream error after $totalRead bytes: ${e.message}",
                        e
                    )
                } else {
                    Log.d(
                        LOG_TAG,
                        "Downstream stopped after $totalRead bytes: ${e.message}"
                    )
                }
            } finally {
                if (totalRead == 0 && !isClosed) {
                    Log.e(
                        LOG_TAG,
                        "Downstream loop exiting with NO DATA for ${getDisplayKey()}"
                    )
                } else {
                    android.util.Log.i(
                        LOG_TAG,
                        "Downstream loop exiting after $totalRead bytes for ${getDisplayKey()}"
                    )
                }

                if (!isClosed) {
                    closeConnection()
                }
            }
        }

    private object LogNoiseLimiter {
        private data class Entry(var lastTs: Long, var suppressed: Int, var lastMsgHash: Int)
        private val map = java.util.concurrent.ConcurrentHashMap<String, Entry>()
        private fun now() = android.os.SystemClock.uptimeMillis()

        fun log(
            tag: String,
            key: String,
            level: Char,
            intervalMs: Long = 800,
            build: () -> String
        ) {
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
        scope.launch {
        var offset = 0
        while (offset < data.size && !isClosed) {
            val chunkSize = min(mss, data.size - offset)
            val chunk = data.copyOfRange(offset, offset + chunkSize)
            
            val packetSeq = (serverSeq + offset) and 0xFFFFFFFFL
            
            // 记录发送时间用于RTT测量
            sentTimeMap[packetSeq + chunkSize] = System.nanoTime()
            
            val packet = IpBuilders.tcpPayloadFromServer(
                    src = ip.dst, dst = ip.src,
                    srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                    payload = chunk,
                    seq = packetSeq.toInt(),
                    ack = clientNextSeq.toInt(),
                    flags = 0x10,
                    window = calcAdvertisedWindowField()
                )

                packetWriter(listOf(packet), listOf(ConnectionManager.PROTO_IPV4))
                offset += chunkSize
            }

            if (packets.isNotEmpty()) {
                packetWriter(packets.toList(), protocols.toList())
            }
            // 修复点：在循环结束后，统一更新 serverSeq
            serverSeq = (serverSeq + offset) and 0xFFFFFFFFL
        }
    }

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
            flags = 0x11,
            window = calcAdvertisedWindowField()
        )
        packetWriter(listOf(finPacket), listOf(ConnectionManager.PROTO_IPV4))
        Log.d(LOG_TAG, "Sent FIN|ACK to client for ${getDisplayKey()}")
    }

    private suspend fun tryFlushUpstream() = withContext(Dispatchers.IO) {
        val writer = upstreamWriter ?: return@withContext
        var totalFlushed = 0

        if (!warmupDone && totalFlushed == 0 && phase == Phase.SOCKS_PRIMED && !bypassDirect) {
            warmupDone = true
        }

        while (canWrite && !outputShutdown) {
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
                    if (!canWrite || outputShutdown || !isSocketHealthy()) {
                        pendingLock.withLock {
                            pending.addFirst(chunk)
                            pendingSize.addAndGet(chunk.size)
                        }
                        return@withLock
                    }

                    val success = writeCoalescer.offer(chunk) { data: ByteArray ->
                        try {
                            if (!canWrite || outputShutdown) {
                                return@offer false
                            }

                            writer.write(data)
                            writer.flush()
                            totalFlushed += data.size
                            true
                        } catch (e: IOException) {
                            Log.e(LOG_TAG, "Write failed: ${e.message}")
                            canWrite = false
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

    @Volatile
    private var outputShutdown = false
    private suspend fun cleanupPendingData() {
        try {
            writeLock.withLock {
                if (!canWrite || outputShutdown) {
                    return@withLock
                }

                if (isSocketHealthy() && upstreamWriter != null) {
                    writeCoalescer.flush { data ->
                        try {
                            if (canWrite && !outputShutdown && isSocketHealthy()) {
                                upstreamWriter?.write(data)
                                upstreamWriter?.flush()
                                true
                            } else {
                                false
                            }
                        } catch (e: Exception) {
                            Log.d(LOG_TAG, "Final flush exception: ${e.message}")
                            canWrite = false
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
                // 修复点：FIN包的处理逻辑已经在 handleFIN 中处理，此处改为立即半关闭
                if (!outputShutdown) {
                    kotlin.runCatching {
                        upstream?.shutdownOutput()
                        outputShutdown = true
                    }
                    Log.d(
                        LOG_TAG,
                        "Upstream output half-closed after pending data flush"
                    )
                }
                canWrite = false
            }
        }
    }


    private fun isSeqBefore(seq1: Long, seq2: Long): Boolean {
        val diff = (seq1 - seq2) and 0xFFFFFFFFL
        return diff > 0x80000000L
    }


    fun closeConnection() {
        if (!closedOnce.compareAndSet(false, true)) {
            Log.d(LOG_TAG, "Connection already closing/closed for ${getDisplayKey()}")
            return
        }

        Log.d(LOG_TAG, "Starting connection close for ${getDisplayKey()}")

        isClosed = true
        canWrite = false

        scope.coroutineContext.cancelChildren()

        cleanupScope.launch {
            try {
                delay(100)
                ackFlushJob?.cancelAndJoin()
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
                            // 修复点：避免在 closeConnection() 中重复半关闭
                            if (!socket.isOutputShutdown) {
                                socket.shutdownOutput()
                            }
                            if (bypassDirect && socket.isConnected) {
                                SocketPool.release(socket)
                            } else {
                                socket.close()
                            }
                        }
                    }
                }
            } finally {
                cleanupScope.cancel()
            }
        }
    }
}