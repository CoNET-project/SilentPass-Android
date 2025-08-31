package com.silentPass.vpn.vpn2socks

import android.util.Log
import android.os.SystemClock
import androidx.multidex.BuildConfig
import kotlinx.coroutines.*
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

    // ====== 通用日志节流（200ms）======
    private val logWindowMs = 200L
    private val lastLogAt = ConcurrentHashMap<String, Long>()
    private fun log(msg: String) { Log.d(LOG_TAG, msg) }
    private fun logThrottled(key: String, line: String) {
        val now = SystemClock.elapsedRealtime()
        val last = lastLogAt[key]
        if (last == null || now - last >= logWindowMs) {
            lastLogAt[key] = now
            Log.d(LOG_TAG, line)
        }
    }

    // ====== DNS 拦截日志合并器（按 srcIP->dstIP:53 聚合）======
    private data class DnsAgg(
        @Volatile var windowStartMs: Long,
        val count: AtomicInteger = AtomicInteger(0),
        val samplePorts: MutableList<Int> = ArrayList(4)
    )
    private val dnsAggMap = ConcurrentHashMap<String, DnsAgg>() // key: "$src->$dst:53"

    private fun onDnsInterceptLog(srcIp: String, dstIp: String, srcPort: Int) {
        val key = "$srcIp->$dstIp:53"
        val now = SystemClock.elapsedRealtime()
        val rec = dnsAggMap.compute(key) { _, old ->
            val r = old ?: DnsAgg(windowStartMs = now)
            // 同一窗口内累计
            if (now - r.windowStartMs < logWindowMs) {
                r.count.incrementAndGet()
                if (r.samplePorts.size < 3) r.samplePorts.add(srcPort)
                r
            } else {
                // 窗口到期，先输出上一窗口汇总
                val prevCount = r.count.get()
                if (prevCount > 0) {
                    val portsTxt = if (r.samplePorts.isNotEmpty())
                        r.samplePorts.joinToString(",")
                    else "-"
                    Log.d(LOG_TAG, "Intercepted $prevCount DNS queries to $dstIp:53 from ports [$portsTxt] (last ${logWindowMs}ms)")
                }
                // 重置窗口，记录当前这次
                r.windowStartMs = now
                r.count.set(1)
                r.samplePorts.clear()
                r.samplePorts.add(srcPort)
                r
            }
        }
        // 为避免“尾窗”丢失，安排一个延迟 flush
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
                val portsTxt = if (rec.samplePorts.isNotEmpty())
                    rec.samplePorts.joinToString(",")
                else "-"
                Log.d(LOG_TAG, "Intercepted $c DNS queries to ${key.substringAfter("->")} from ports [$portsTxt] (last ${logWindowMs}ms)")
                rec.samplePorts.clear()
            }
        }
    }

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

    init {
        // 定期清理已关闭的连接
        scope.launch {
            while (isActive) {
                delay(30_000)
                cleanupClosedConnections()
                SocketPool.cleanup()  // 添加Socket池清理
                // 顺便 flush 所有 DNS 聚合尾窗，避免长期不活动时残留
                dnsAggMap.keys.forEach { flushDnsAggIfIdle(it) }
            }
        }
    }

    private fun handleUDP(ip: IPv4Packet) {
        val udp = UDPDatagram(ip.payload)

        // 仅拦截 DNS，其他 UDP 返回 ICMP Port Unreachable
        if (udp.dstPort == 53) {
            // 合并节流：把同窗内多条端口日志汇总为一条
            onDnsInterceptLog(ip.src.toString(), ip.dst.toString(), udp.srcPort)

            scope.launch {
                try {
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
                        Log.e(LOG_TAG, "DNS query returned null - upstream DNS likely failed")
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

    private fun handleICMP(ip: IPv4Packet) {
        // 暂无处理
    }

    private fun handleTCP(ip: IPv4Packet) {
        val tcp = TCPSegment(ip.payload)
        val key = "${ip.src}:${tcp.srcPort}->${ip.dst}:${tcp.dstPort}"

        if (tcp.isSYN && !tcp.isACK) {
            Log.d(LOG_TAG, "SYN ${ip.src}:${tcp.srcPort} -> ${ip.dst}:${tcp.dstPort}")
        }

        // 阻断 DoT (port 853) —— 直接 RST
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

        // 是否为“假段”范围的 IP（198.18.0.0/15）
        val v = ip.dst.raw
        val firstOctet = (v ushr 24) and 0xff
        val secondOctet = (v ushr 16) and 0xff
        val isFakeByRange = (firstOctet == 198) && (secondOctet == 18 || secondOctet == 19)

        // 通过 fake DNS 是否解析到域名
        val domain = dns.lookupDomain(ip.dst)
        val hasDomainMapping = (domain != null)

        // 是否为直连白名单域名
        val isBypassDomain = domain?.let { dns.shouldBypass(it) } ?: false

        // 路由判定
        val bypassDirect = when {
            isBypassDomain -> true
            isFakeByRange -> false
            hasDomainMapping && !isBypassDomain -> false
            else -> true
        }

        scope.launch {
            // 连接判定日志：按 key 节流
            if (verbose) {
                logThrottled(
                    key,
                    "TCP connection key: $key, isFakeRange=$isFakeByRange, domain=$domain, isBypassDomain=$isBypassDomain, bypassDirect=$bypassDirect"
                )
            }

            val conn = tcpConns.getOrPut(key) {
                TCPConnection(
                    key = key,
                    mtu = mtu,
                    packetWriter = packetWriter,
                    dns = dns,
                    socksEndpoint = socksEndpoint,
                    bypassDirect = bypassDirect
                )
            }
            conn.onTcp(ip, tcp)
        }
    }

    companion object {
        const val PROTO_IPV4 = 0x0800
    }
}
