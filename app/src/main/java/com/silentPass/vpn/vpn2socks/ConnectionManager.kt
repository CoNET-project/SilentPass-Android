package com.silentPass.vpn.vpn2socks

import android.util.Log
import androidx.multidex.BuildConfig
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap

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
    private fun log(msg: String) { Log.d(LOG_TAG, msg) }

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
            if (conn.isClosed()) {
                toRemove.add(key)
            }
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
                delay(30000) // 每30秒清理一次
                cleanupClosedConnections()
            }
        }
    }

    private fun handleUDP(ip: IPv4Packet) {
        val udp = UDPDatagram(ip.payload)

        // 仅拦截 DNS，其他 UDP 返回 ICMP Port Unreachable
        if (udp.dstPort == 53) {
            Log.d(LOG_TAG, "Intercepted DNS query to ${ip.dst}:53 from port ${udp.srcPort}")
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
        // 目前不处理
    }



    private fun handleTCP(ip: IPv4Packet) {
        val tcp = TCPSegment(ip.payload)
        val key = "${ip.src}:${tcp.srcPort}->${ip.dst}:${tcp.dstPort}"

        if (tcp.isSYN && !tcp.isACK) {
            Log.d(LOG_TAG, "SYN ${ip.src}:${tcp.srcPort} -> ${ip.dst}:${tcp.dstPort}")
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

        // Determine if this should bypass SOCKS
        val v = ip.dst.raw
        val firstOctet = (v ushr 24) and 0xff
        val secondOctet = (v ushr 16) and 0xff
        val isFakeByRange = (firstOctet == 198) && (secondOctet == 18 || secondOctet == 19)

        // Check if there's a domain mapping for this IP
        val domain = dns.lookupDomain(ip.dst)
        val hasDomainMapping = (domain != null)

        // CRITICAL FIX: Check if the domain is a bypass domain
        val isBypassDomain = if (domain != null) {
            dns.shouldBypass(domain)  // Need to expose this method
        } else {
            false
        }

        // Decision logic:
        // - If it's a fake IP (by range or has non-bypass domain mapping) -> use SOCKS
        // - If it has a bypass domain -> direct connection
        // - Otherwise -> direct connection
        val bypassDirect = when {
            isBypassDomain -> true  // Bypass domains always go direct
            isFakeByRange -> false  // Fake IP range always uses SOCKS
            hasDomainMapping && !isBypassDomain -> false  // Non-bypass domain uses SOCKS
            else -> true  // Everything else goes direct
        }

        scope.launch {
            Log.d(LOG_TAG, "TCP connection key: $key, isFakeRange=$isFakeByRange, domain=$domain, isBypassDomain=$isBypassDomain, bypassDirect=$bypassDirect")
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