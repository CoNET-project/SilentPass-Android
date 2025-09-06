package com.silentPass.vpn.vpn2socks

import android.util.Log
import android.os.SystemClock
import androidx.multidex.BuildConfig
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class ConnectionManager(
    private val mtu: Int,
    private val fakeDns: IPv4Address,
    private val packetWriter: (List<ByteArray>, List<Int>) -> Unit,
    private val dns: DNSInterceptor,
    private val socksEndpoint: SocksEndpoint,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val tcpConns = ConcurrentHashMap<String, TCPConnection>()
    private val verbose = try { BuildConfig.DEBUG } catch (_: Throwable) { true }
    private val LOG_TAG = "ConnectionManager"

    private val connectionPool = Channel<TCPConnection>(Channel.UNLIMITED)

    // Speedtest domain cache for optimization
    private val speedtestDomains = setOf(
        "www.speedtest.net"
    )

    // ====== 通用日志节流（200ms）======


    private fun log(msg: String) { Log.d(LOG_TAG, msg) }

    // ====== DNS 拦截日志合并器（按 srcIP->dstIP:53 聚合）======
    private data class DnsAgg(
        @Volatile var windowStartMs: Long,
        val count: AtomicInteger = AtomicInteger(0),
        val samplePorts: MutableList<Int> = ArrayList(4)
    )



    fun onPacket(pkt: TunPacketIO.TunPacket) {
        val b = pkt.bytes
        if (b.isEmpty()) return

        val version = (b[0].toInt() ushr 4) and 0x0f
        if (version != 4) return
        if (b.size < 20) return

        val ip = IPv4Packet(b)
        when (ip.proto) {
            1  -> handleICMP(ip)
            6  -> handleTCP(ip)
            17 -> handleUDP(ip)
            else -> { /* drop */ }
        }
    }

    private fun cleanupClosedConnections() {
        val toRemove = mutableListOf<String>()
        tcpConns.forEach { (key, conn) ->
            if (conn.isClosed()) toRemove.add(key)
        }
        toRemove.forEach { tcpConns.remove(it) }
        if (toRemove.isNotEmpty()) {
            Log.d(LOG_TAG, "Cleaned up ${toRemove.size} closed connections")
        }
    }

    private fun getOrCreateConnection(
        key: String,
        ip: IPv4Packet,
        tcp: TCPSegment,
        bypassDirect: Boolean  // 添加参数
    ): TCPConnection? {
        // 检查是否有可复用的连接
        val existing = tcpConns[key]
        if (existing != null && !existing.isClosed()) {
            // 检查是否是重传的SYN
            if (tcp.isSYN && !tcp.isACK) {
                Log.d(LOG_TAG, "Duplicate SYN for existing connection: $key")
                return existing
            }
            return existing
        }

        // 创建新连接
        return TCPConnection(
            key = key,
            mtu = mtu,
            packetWriter = packetWriter,
            dns = dns,
            socksEndpoint = socksEndpoint,
            bypassDirect = bypassDirect
        ).also {
            tcpConns[key] = it
        }
    }

    init {
        scope.launch {
            val domainsToPrefetch = listOf(
                // Google services
                "www.google.com",
                "apis.google.com",
                "www.gstatic.com",
                "ssl.gstatic.com",
                "fonts.googleapis.com",
                "ajax.googleapis.com",
                // Other common domains
                "www.speedtest.net",
                "c.speedtest.net",
                "www.youtube.com",
                "www.facebook.com",
                "www.twitter.com",
                "www.instagram.com",
                "www.reddit.com",
                "www.amazon.com",
                "www.netflix.com"
            )

            dns.prefetchDomains(domainsToPrefetch)
            Log.d(LOG_TAG, "DNS prefetch initiated for ${domainsToPrefetch.size} domains")
        }

        // Start connection cleanup coroutine
        scope.launch {
            connectionCleanupLoop()
        }

        // Start metrics collection
        scope.launch {
            metricsCollectionLoop()
        }
    }

    // Connection metrics
    private data class ConnectionMetrics(
        val activeConnections: AtomicInteger = AtomicInteger(0),
        val totalConnections: AtomicInteger = AtomicInteger(0),
        val failedConnections: AtomicInteger = AtomicInteger(0),
        val bytesTransferred: AtomicInteger = AtomicInteger(0)
    )
    private val metrics = ConnectionMetrics()

    private val logWindowMs = 200L
    private val lastLogAt = ConcurrentHashMap<String, Long>()

    private val dnsAggMap = ConcurrentHashMap<String, DnsAgg>()

    private fun handleUDP(ip: IPv4Packet) {
        val udp = UDPDatagram(ip.payload)

        // DNS interception with optimization
        if (udp.dstPort == 53) {
            onDnsInterceptLog(ip.src.toString(), ip.dst.toString(), udp.srcPort)

            scope.launch {
                try {
                    // Check if this is a speedtest domain for priority handling
                    val isSpeedtest = checkIfSpeedtestQuery(udp.payload)

                    if (isSpeedtest) {
                        Log.d(LOG_TAG, "Priority DNS query for Speedtest domain")
                    }

                    val res = dns.handleQuery(udp.payload)
                    if (res != null) {
                        val (resp, _) = res
                        val out = IpBuilders.udpFrom(
                            src = ip.dst,
                            dst = ip.src,
                            srcPort = 53,
                            dstPort = udp.srcPort,
                            payload = resp
                        )
                        packetWriter(listOf(out), listOf(PROTO_IPV4))
                    } else {
                        Log.e(LOG_TAG, "DNS query returned null")
                    }
                } catch (t: Throwable) {
                    Log.e(LOG_TAG, "DNS handling failed: ${t.message}", t)
                }
            }
        } else {
            val icmp = IpBuilders.icmpPortUnreachable(ip)
            packetWriter(listOf(icmp), listOf(PROTO_IPV4))
        }
    }

    private fun checkIfSpeedtestQuery(payload: ByteArray): Boolean {
        // Quick check for speedtest domains in DNS query
        try {
            val query = String(payload).lowercase()
            return speedtestDomains.any { domain ->
                query.contains(domain.replace("*.", ""))
            }
        } catch (e: Exception) {
            return false
        }
    }

    private fun handleICMP(ip: IPv4Packet) {
        // Implement ICMP echo reply for better connectivity checks
        val icmp = ip.payload
        if (icmp.size >= 8 && icmp[0] == 8.toByte()) { // Echo Request
            val reply = IpBuilders.icmpEchoReply(ip)
            packetWriter(listOf(reply), listOf(PROTO_IPV4))
        }
    }

    private fun handleTCP(ip: IPv4Packet) {
        val tcp = TCPSegment(ip.payload)
        val key = "${ip.src}:${tcp.srcPort}->${ip.dst}:${tcp.dstPort}"

        if (tcp.isSYN && !tcp.isACK) {
            Log.d(LOG_TAG, "SYN ${ip.src}:${tcp.srcPort} -> ${ip.dst}:${tcp.dstPort}")
            metrics.totalConnections.incrementAndGet()
        }

        // Block DoT (port 853)
        if (tcp.isSYN && !tcp.isACK && tcp.dstPort == 853) {
            val rst = IpBuilders.tcpPayloadFromServer(
                src = ip.dst, dst = ip.src,
                srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                payload = ByteArray(0),
                seq = 0,
                ack = (tcp.seq.toInt() + 1),
                flags = 0x14, // RST | ACK
                window = 0
            )
            packetWriter(listOf(rst), listOf(PROTO_IPV4))
            return
        }

        // Determine routing based on IP and domain
        val v = ip.dst.raw
        val firstOctet = (v ushr 24) and 0xff
        val secondOctet = (v ushr 16) and 0xff
        val isFakeByRange = (firstOctet == 198) && (secondOctet == 18 || secondOctet == 19)

        val domain = dns.lookupDomain(ip.dst)
        val hasDomainMapping = (domain != null)
        val isBypassDomain = domain?.let { dns.shouldBypass(it) } ?: false

        // Check if it's a speedtest domain for optimization
        val isSpeedtest = domain?.let { d ->
            speedtestDomains.any { pattern ->
                if (pattern.startsWith("*.")) {
                    d.endsWith(pattern.substring(2))
                } else {
                    d == pattern || d.endsWith(".$pattern")
                }
            }
        } ?: false

        val bypassDirect = when {
            isBypassDomain -> true
            isFakeByRange -> false
            hasDomainMapping && !isBypassDomain -> false
            else -> true
        }

        scope.launch {
            if (verbose) {
                logThrottled(
                    key,
                    "TCP: $key, domain=$domain, bypass=$bypassDirect, speedtest=$isSpeedtest"
                )
            }

            // Get or create connection with optimization for speedtest
            val conn = tcpConns.getOrPut(key) {
                val newConn = TCPConnection(
                    key = key,
                    mtu = mtu,
                    packetWriter = packetWriter,
                    dns = dns,
                    socksEndpoint = socksEndpoint,
                    bypassDirect = bypassDirect
                )

                metrics.activeConnections.incrementAndGet()
                newConn
            }

            conn.onTcp(ip, tcp)
        }
    }

    private suspend fun connectionCleanupLoop() {
        while (scope.isActive) {
            delay(30_000)

            val closedConnections = tcpConns.filter { it.value.isClosed() }
            val closedCount = closedConnections.size

            closedConnections.forEach { (key, _) ->
                tcpConns.remove(key)
                metrics.activeConnections.decrementAndGet()
            }

            if (closedCount > 0) {
                Log.d(LOG_TAG, "Cleaned up $closedCount closed connections")
            }

            // Force cleanup of socket pool
            SocketPool.cleanup()

            // Clean DNS aggregation windows
            dnsAggMap.keys.forEach { flushDnsAggIfIdle(it) }

            // Log current status
            Log.d(LOG_TAG, "Active: ${metrics.activeConnections.get()}, " +
                    "Total: ${metrics.totalConnections.get()}, " +
                    "Failed: ${metrics.failedConnections.get()}")
        }
    }

    private suspend fun metricsCollectionLoop() {
        while (scope.isActive) {
            delay(60_000) // Every minute

            val activeConns = metrics.activeConnections.get()
            val totalConns = metrics.totalConnections.get()
            val failedConns = metrics.failedConnections.get()

            if (totalConns > 0) {
                val successRate = ((totalConns - failedConns).toFloat() / totalConns * 100).toInt()
                Log.i(LOG_TAG, "Connection stats - Active: $activeConns, Success rate: $successRate%")
            }
        }
    }

    private fun onDnsInterceptLog(srcIp: String, dstIp: String, srcPort: Int) {
        val key = "$srcIp->$dstIp:53"
        val now = SystemClock.elapsedRealtime()

        dnsAggMap.compute(key) { _, old ->
            val r = old ?: DnsAgg(windowStartMs = now)

            if (now - r.windowStartMs < logWindowMs) {
                r.count.incrementAndGet()
                if (r.samplePorts.size < 3) r.samplePorts.add(srcPort)
                r
            } else {
                val prevCount = r.count.get()
                if (prevCount > 0) {
                    val portsTxt = r.samplePorts.joinToString(",").ifEmpty { "-" }
                    Log.d(LOG_TAG, "DNS: $prevCount queries to $dstIp:53 from [$portsTxt]")
                }

                r.windowStartMs = now
                r.count.set(1)
                r.samplePorts.clear()
                r.samplePorts.add(srcPort)
                r
            }
        }

        scope.launch {
            delay(logWindowMs + 5)
            flushDnsAggIfIdle(key)
        }
    }

    private fun flushDnsAggIfIdle(key: String) {
        val now = SystemClock.elapsedRealtime()
        val rec = dnsAggMap[key] ?: return

        if (now - rec.windowStartMs >= logWindowMs) {
            val c = rec.count.getAndSet(0)
            if (c > 0) {
                val portsTxt = rec.samplePorts.joinToString(",").ifEmpty { "-" }
                Log.d(LOG_TAG, "DNS: $c queries to ${key.substringAfter("->")} from [$portsTxt]")
                rec.samplePorts.clear()
            }
        }
    }

    private fun logThrottled(key: String, line: String) {
        val now = SystemClock.elapsedRealtime()
        val last = lastLogAt[key]
        if (last == null || now - last >= logWindowMs) {
            lastLogAt[key] = now
            Log.d(LOG_TAG, line)
        }
    }

    fun shutdown() {
        scope.cancel()
        tcpConns.values.forEach {
            try {
                it.closeConnection()
            } catch (e: Exception) {
                Log.w(LOG_TAG, "Error closing connection: ${e.message}")
            }
        }
        tcpConns.clear()
        dns.close()
    }

    companion object {
        const val PROTO_IPV4 = 0x0800
    }
}
