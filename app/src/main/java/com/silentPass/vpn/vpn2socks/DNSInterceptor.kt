package com.silentPass.vpn.vpn2socks

import android.util.Log
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory

class DNSInterceptor {
    private val LOG_TAG = "DNSInterceptor"
    private val bypassCache = HashMap<String, Boolean>()
    // 归一化：去掉前导 "*." 或 "."，去掉尾部点，转小写
    private fun normalizeDomain(d: String): String =
        d.trim().trim('.').removePrefix("*.").removePrefix(".").lowercase()


    // 需要直连的域名（含 APNs/FCM/自管域等）
    private val bypassDomains = setOf(
        // Apple / APNs
        "apple.com", "push.apple.com", "icloud.com", "gsp-ssl.ls.apple.com",
        "gateway.push.apple.com", "gateway.sandbox.push.apple.com",
        "mesu.apple.com", "gdmf.apple.com",
        // 你自管域
        "conet.network", "silentpass.io", "openpgp.online",
        // 常见国内 IM/CDN
        "weixin.qq.com", "wechat.com", "qpic.cn", "qlogo.cn", "wx.gtimg.com",
        // 测试
        "google.com","gstatic.com","gvt3.com","comm100vue.com","gvt2.com","googleusercontent.com","fastly-edge.com"
    )
    // 预处理一份“规范化后的”绕行域名集合（保持原 bypassDomains 不动）
    private val bypassNorm: Set<String> = bypassDomains.map { normalizeDomain(it) }.toSet()
    // 严格的“标签边界后缀匹配”
    // 例：若 base = "google.com"，则 "google.com"、"a.google.com"、"a.b.google.com" 均返回 true，
    // 而 "evilgoogle.com"、"google.com.evil.com" 返回 false。
    private fun isSubdomainOf(domain: String, base: String): Boolean {
        if (domain == base) return true
        // 必须以 ".base" 结尾，确保标签边界
        return domain.endsWith(".$base")
    }
    private val directIPs = HashSet<Int>()
    private val directMutex = Mutex()

    private val ipToDomain = HashMap<Int, String>()
    private val domainToIp = HashMap<String, Int>()

    private val allocator = FakeIPAllocator(
        listOf(IPv4Range("198.18.0.0/15")),
        setOf(IPv4Address.parse("198.18.0.0")!!.raw, IPv4Address.parse("198.19.255.255")!!.raw)
    )

    // OkHttp 客户端，使用自定义 SocketFactory
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .socketFactory(ProtectedSocketFactory())
        .build()

    // 自定义 SocketFactory 确保 socket 被保护
    inner class ProtectedSocketFactory : SocketFactory() {
        override fun createSocket(): Socket {
            val socket = Socket()
            if (!Vpn2SocksService.protectSocket(socket)) {
                Log.w(LOG_TAG, "Failed to protect socket in factory")
            }
            return socket
        }

        override fun createSocket(host: String?, port: Int): Socket {
            return createSocket().apply {
                connect(java.net.InetSocketAddress(host, port))
            }
        }

        override fun createSocket(host: String?, port: Int, localHost: java.net.InetAddress?, localPort: Int): Socket {
            return createSocket().apply {
                bind(java.net.InetSocketAddress(localHost, localPort))
                connect(java.net.InetSocketAddress(host, port))
            }
        }

        override fun createSocket(host: java.net.InetAddress?, port: Int): Socket {
            return createSocket().apply {
                connect(java.net.InetSocketAddress(host, port))
            }
        }

        override fun createSocket(address: java.net.InetAddress?, port: Int, localAddress: java.net.InetAddress?, localPort: Int): Socket {
            return createSocket().apply {
                bind(java.net.InetSocketAddress(localAddress, localPort))
                connect(java.net.InetSocketAddress(address, port))
            }
        }
    }

    // 主查询方法：优先使用 DoH
    private fun queryOverUpstreams(query: ByteArray): ByteArray? {
        // 首先尝试 DoH
        val dohResult = queryViaDoH(query)
        if (dohResult != null) {
            Log.d(LOG_TAG, "DoH query successful")
            return dohResult
        }

        // DoH 失败，尝试 TCP DNS（作为备用）
        Log.w(LOG_TAG, "DoH failed, falling back to TCP DNS")
        return queryViaTraditionalTCP(query)
    }

    // DNS-over-HTTPS 实现
    private fun queryViaDoH(query: ByteArray): ByteArray? {
        val providers = listOf(
            "https://1.1.1.1/dns-query",
            "https://cloudflare-dns.com/dns-query",
            "https://8.8.8.8/dns-query",
            "https://dns.google/dns-query"
        )

        // 先尝试 POST 方法（更可靠）
        for (provider in providers) {
            try {
                Log.d(LOG_TAG, "Trying DoH POST to: $provider")

                // 使用新的 API
                val requestBody = query.toRequestBody("application/dns-message".toMediaType())

                val request = Request.Builder()
                    .url(provider)
                    .post(requestBody)
                    .addHeader("Accept", "application/dns-message")
                    .addHeader("Content-Type", "application/dns-message")
                    .build()

                val response = httpClient.newCall(request).execute()
                if (response.isSuccessful) {
                    // 使用新的属性访问方式
                    val responseBytes = response.body?.bytes()
                    response.close()
                    if (responseBytes != null) {
                        Log.d(LOG_TAG, "DoH POST successful from $provider")
                        return responseBytes
                    }
                } else {
                    // 使用新的属性访问方式
                    Log.w(LOG_TAG, "DoH POST failed with code ${response.code} from $provider")
                    response.close()
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "DoH POST error for $provider: ${e.message}")
            }
        }

        // 如果 POST 失败，尝试 GET 方法
        for (provider in providers) {
            try {
                Log.d(LOG_TAG, "Trying DoH GET to: $provider")

                // 将查询转换为 base64url（无填充）
                val base64Query = android.util.Base64.encodeToString(
                    query,
                    android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
                )

                val url = "$provider?dns=$base64Query"
                val request = Request.Builder()
                    .url(url)
                    .get()
                    .addHeader("Accept", "application/dns-message")
                    .build()

                val response = httpClient.newCall(request).execute()
                if (response.isSuccessful) {
                    // 使用新的属性访问方式
                    val responseBytes = response.body?.bytes()
                    response.close()
                    if (responseBytes != null) {
                        Log.d(LOG_TAG, "DoH GET successful from $provider")
                        return responseBytes
                    }
                } else {
                    // 使用新的属性访问方式
                    Log.w(LOG_TAG, "DoH GET failed with code ${response.code} from $provider")
                    response.close()
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "DoH GET error for $provider: ${e.message}")
            }
        }

        return null
    }

    // 备用：传统 TCP DNS
    private fun queryViaTraditionalTCP(query: ByteArray): ByteArray? {
        val servers = arrayOf(
            java.net.InetSocketAddress("8.8.8.8", 53),
            java.net.InetSocketAddress("1.1.1.1", 53)
        )

        for (addr in servers) {
            val result = upstreamTcp(query, addr)
            if (result != null) return result
        }

        return null
    }

    // TCP/53 查询（RFC 7766）
    private fun upstreamTcp(query: ByteArray, addr: java.net.InetSocketAddress): ByteArray? {
        try {
            Log.d(LOG_TAG, "Trying upstream DNS (TCP): $addr")
            val sock = Socket()

            if (!Vpn2SocksService.protectSocket(sock)) {
                Log.e(LOG_TAG, "Failed to protect TCP socket for $addr")
                sock.close()
                return null
            }

            sock.tcpNoDelay = true
            sock.soTimeout = 5000
            sock.connect(addr, 4000)

            val out = sock.getOutputStream()
            val inp = sock.getInputStream()

            // TCP DNS 带 2 字节长度前缀
            val qlen = query.size
            out.write(byteArrayOf(((qlen ushr 8) and 0xff).toByte(), (qlen and 0xff).toByte()))
            out.write(query)
            out.flush()

            // 读 2 字节长度
            val hdr = ByteArray(2)
            var n = 0
            while (n < 2) {
                val r = inp.read(hdr, n, 2 - n)
                if (r < 0) throw java.io.EOFException("EOF reading TCP DNS length")
                n += r
            }
            val len = ((hdr[0].toInt() and 0xff) shl 8) or (hdr[1].toInt() and 0xff)
            if (len <= 0 || len > 4096) throw IllegalStateException("Bad TCP DNS length: $len")

            val resp = ByteArray(len)
            var off = 0
            while (off < len) {
                val r = inp.read(resp, off, len - off)
                if (r < 0) throw java.io.EOFException("EOF reading TCP DNS payload")
                off += r
            }

            sock.close()
            Log.d(LOG_TAG, "Upstream DNS response (TCP) from $addr")
            return resp
        } catch (e: Throwable) {
            Log.e(LOG_TAG, "Upstream DNS failed (TCP) for $addr: ${e.message}")
            return null
        }
    }

    // 以下所有方法保持不变...
    private val mutex = Mutex()

    // Change from private to public
    fun shouldBypass(domain: String): Boolean {
        val d = normalizeDomain(domain)
        bypassCache[d]?.let { return it }

        // 直接命中或任一后缀命中
        val hit = bypassNorm.contains(d) || bypassNorm.any { base -> isSubdomainOf(d, base) }
        bypassCache[d] = hit
        return hit
    }

    suspend fun isDirect(ip: IPv4Address): Boolean =
        directMutex.withLock { directIPs.contains(ip.raw) }

    private suspend fun allocOrGet(domain: String): IPv4Address? = mutex.withLock {
        val d = domain.trim('.').lowercase()
        if (shouldBypass(d)) {
            domainToIp.remove(d)?.let { ipToDomain.remove(it) }
            return null
        }
        domainToIp[d]?.let { return IPv4Address(it) }

        val ip = allocator.allocate() ?: return null
        ipToDomain[ip.raw] = d
        domainToIp[d] = ip.raw
        return ip
    }

    fun lookupDomain(ip: IPv4Address): String? = ipToDomain[ip.raw]

    suspend fun handleQuery(query: ByteArray): Pair<ByteArray, IPv4Address?>? {
        if (query.size < 12) return null
        Log.d(LOG_TAG, "DNS Query received for parsing")

        val id = ((query[0].toInt() and 0xff) shl 8) or (query[1].toInt() and 0xff)
        val qdCount = ((query[4].toInt() and 0xff) shl 8) or (query[5].toInt() and 0xff)
        if (qdCount != 1) return null

        val (name, off) = parseQName(query, 12)
        if (off < 0 || off + 4 > query.size) {
            val resp = queryOverUpstreams(query)
            return resp?.let { it to null }
        }
        val qtype = ((query[off].toInt() and 0xff) shl 8) or (query[off + 1].toInt() and 0xff)
        Log.i(LOG_TAG, "Q: id=$id name=$name qtype=$qtype")
        Log.d(LOG_TAG, "Parsed domain name: $name")

        if (shouldBypass(name)) {
            Log.d(LOG_TAG, "Bypass domain: $name (direct connection)")
            val resp = queryOverUpstreams(query)
            if (resp != null && qtype == 1) {
                val ips = parseARecords(resp)
                if (ips.isNotEmpty()) {
                    directMutex.withLock {
                        val d = name.trim('.').lowercase()
                        ips.forEach {
                            directIPs.add(it.raw)
                            ipToDomain[it.raw] = d          // ★ 新增：建立反查
                            Log.d(LOG_TAG, "Registered direct IP: $it for domain: $d")
                        }
                    }
                }
            }
            return resp?.let { it to null }
        }

        if (qtype != 1) {
            val resp = queryOverUpstreams(query)
            return resp?.let { it to null }
        }

        val fake = allocOrGet(name) ?: run {
            Log.e(LOG_TAG, "Failed to allocate fake IP for $name")
            val resp = queryOverUpstreams(query)
            return resp?.let { it to null }
        }

        Log.d(LOG_TAG, "Allocated fake IP $fake for $name")
        val answer = buildAResponse(
            id = id,
            query = query,
            qname = name,
            ip = ByteBuffer.allocate(4).apply {
                put(((fake.raw ushr 24) and 0xff).toByte())
                put(((fake.raw ushr 16) and 0xff).toByte())
                put(((fake.raw ushr 8) and 0xff).toByte())
                put((fake.raw and 0xff).toByte())
            }.array(),
            ttl = 30
        )
        return answer to fake
    }

    private fun parseARecords(resp: ByteArray): List<IPv4Address> {
        if (resp.size < 12) return emptyList()
        fun u16(i: Int) = ((resp[i].toInt() and 0xff) shl 8) or (resp[i+1].toInt() and 0xff)
        var p = 12
        while (p < resp.size) {
            val l = resp[p].toInt() and 0xff
            p++
            if (l == 0) break
            if ((l and 0xC0) == 0xC0) { p++; break }
            p += l
        }
        p += 4
        val anCount = u16(6)
        val out = ArrayList<IPv4Address>()
        repeat(anCount) {
            if (p >= resp.size) return out
            val tag = resp[p].toInt() and 0xff
            p += if ((tag and 0xC0) == 0xC0) 2 else {
                var q = p
                while (q < resp.size && resp[q].toInt() != 0) {
                    val ll = resp[q].toInt() and 0xff
                    q += 1 + ll
                }
                (q - p) + 1
            }
            if (p + 10 > resp.size) return out
            val type = u16(p)
            val cls = u16(p + 2)
            val rdlen = u16(p + 8)
            p += 10
            if (p + rdlen > resp.size) return out
            if (type == 1 && cls == 1 && rdlen == 4) {
                val a = ((resp[p].toInt() and 0xff) shl 24) or
                        ((resp[p+1].toInt() and 0xff) shl 16) or
                        ((resp[p+2].toInt() and 0xff) shl 8) or
                        (resp[p+3].toInt() and 0xff)
                out.add(IPv4Address(a))
            }
            p += rdlen
        }
        return out
    }

    private fun parseQName(msg: ByteArray, start: Int): Pair<String, Int> {
        var i = start
        val parts = ArrayList<String>()
        while (true) {
            if (i >= msg.size) return "" to -1
            val len = msg[i].toInt() and 0xff
            i += 1
            when {
                len == 0 -> break
                (len and 0xC0) == 0xC0 -> return "" to -1
                len > 63 || i + len > msg.size -> return "" to -1
                else -> {
                    val label = String(msg, i, len, Charsets.UTF_8)
                    parts.add(label); i += len
                }
            }
        }
        val name = parts.joinToString(".")
        return name to i
    }

    private fun buildAResponse(
        id: Int,
        query: ByteArray,
        qname: String,
        ip: ByteArray,
        ttl: Int
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf((id shr 8).toByte(), (id and 0xff).toByte()))
        val rd = (query[2].toInt() and 0x01)
        val flHigh = 0x81 or (rd shl 0)
        val flLow  = 0x80
        out.write(byteArrayOf(flHigh.toByte(), flLow.toByte()))
        out.write(byteArrayOf(0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00))
        out.write(query, 12, query.size - 12)
        out.write(byteArrayOf(0xC0.toByte(), 0x0C))
        out.write(byteArrayOf(0x00,0x01, 0x00,0x01))
        out.write(byteArrayOf(
            ((ttl ushr 24) and 0xff).toByte(),
            ((ttl ushr 16) and 0xff).toByte(),
            ((ttl ushr 8)  and 0xff).toByte(),
            ( ttl         and 0xff).toByte()
        ))
        out.write(byteArrayOf(0x00,0x04))
        require(ip.size == 4)
        out.write(ip)
        return out.toByteArray()
    }
}