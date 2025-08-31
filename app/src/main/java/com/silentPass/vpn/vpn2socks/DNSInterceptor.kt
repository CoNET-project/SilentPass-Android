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
import java.util.concurrent.atomic.AtomicInteger
import javax.net.SocketFactory

class DNSInterceptor {

	companion object {
		private val initGate = java.util.concurrent.CountDownLatch(1)
		private val initDone = java.util.concurrent.atomic.AtomicBoolean(false)
		private val lastInitWarnAt = java.util.concurrent.atomic.AtomicLong(0L)
		fun signalReady() {
			if (initDone.compareAndSet(false, true)) initGate.countDown()
		}
		fun awaitReady(timeoutMs: Long): Boolean {
			if (initDone.get()) return true
			return try { initGate.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS) } catch (_: InterruptedException) { false }
		}
		fun throttledInitWarn(msg: String) {
			val now = System.currentTimeMillis()
			val prev = lastInitWarnAt.get()
			if (now - prev >= 1000L && lastInitWarnAt.compareAndSet(prev, now)) {
				android.util.Log.w("DNSInterceptor", msg)
			}
		}
	}

    @Volatile
    private var initialized = false

    private val LOG_TAG = "DNSInterceptor"
    private val bypassCache = HashMap<String, Boolean>()

    // DNS 查询缓存相关
    data class DNSCacheEntry(
        val response: ByteArray,
        val timestamp: Long,
        val ttl: Long = 300000L // 默认 5 分钟 TTL (毫秒)
    ) {
        fun isExpired(): Boolean {
            return System.currentTimeMillis() - timestamp > ttl
        }
    }

    private val dnsCache = HashMap<String, DNSCacheEntry>()
    private val dnsCacheMutex = Mutex()
    private val MAX_CACHE_SIZE = 1000 // 最大缓存条目数

    init {
        // 等待 VPN 服务就绪
        Thread {
            var attempts = 0
            while (!initialized && attempts < 20) {
                try {
                    // 测试创建一个 socket 看是否能保护
                    val testSocket = Socket()
                    val protected = Vpn2SocksService.protectSocket(testSocket)
                    testSocket.close()

                    if (protected) {
                        initialized = true
                        Log.d(LOG_TAG, "DNSInterceptor initialized successfully")
                    } else {
                        Thread.sleep(100)
                        attempts++
                    }
                } catch (e: Exception) {
                    Thread.sleep(100)
                    attempts++
                }
            }

            if (!initialized) {
                Log.e(LOG_TAG, "DNSInterceptor initialization timeout")
            }

        }.start()
    }


    // 生成缓存键：基于查询内容（跳过 ID 字段）
    private fun generateCacheKey(query: ByteArray): String {
        if (query.size < 12) return ""

        // 跳过前两个字节（Transaction ID），从第3个字节开始计算
        val keyBytes = ByteArrayOutputStream()
        keyBytes.write(query, 2, query.size - 2)

        // 使用 Base64 编码作为键
        return android.util.Base64.encodeToString(
            keyBytes.toByteArray(),
            android.util.Base64.NO_WRAP
        )
    }

    // 从缓存响应中提取 TTL
    private fun extractTTLFromResponse(response: ByteArray): Long {
        try {
            if (response.size < 12) return 300000L // 默认 5 分钟

            // 简单解析：跳过 header 和 question section，查找第一个 answer 的 TTL
            var pos = 12

            // 跳过 question section
            val qdCount = ((response[4].toInt() and 0xff) shl 8) or (response[5].toInt() and 0xff)
            repeat(qdCount) {
                // 跳过 domain name
                while (pos < response.size && response[pos].toInt() != 0) {
                    val len = response[pos].toInt() and 0xff
                    if ((len and 0xC0) == 0xC0) {
                        pos += 2
                        break
                    } else {
                        pos += 1 + len
                    }
                }
                if (response[pos].toInt() == 0) pos++ // null terminator
                pos += 4 // skip QTYPE and QCLASS
            }

            // 读取第一个 answer 的 TTL
            val anCount = ((response[6].toInt() and 0xff) shl 8) or (response[7].toInt() and 0xff)
            if (anCount > 0 && pos < response.size) {
                // 跳过 answer name
                if ((response[pos].toInt() and 0xC0) == 0xC0) {
                    pos += 2
                } else {
                    while (pos < response.size && response[pos].toInt() != 0) {
                        val len = response[pos].toInt() and 0xff
                        pos += 1 + len
                    }
                    pos++ // null terminator
                }

                if (pos + 10 <= response.size) {
                    // 跳过 TYPE (2) 和 CLASS (2)
                    pos += 4
                    // 读取 TTL (4 bytes)
                    val ttl = ((response[pos].toLong() and 0xff) shl 24) or
                            ((response[pos + 1].toLong() and 0xff) shl 16) or
                            ((response[pos + 2].toLong() and 0xff) shl 8) or
                            (response[pos + 3].toLong() and 0xff)

                    // 转换为毫秒，限制在合理范围内
                    val ttlMs = ttl * 1000L
                    return when {
                        ttlMs < 60000L -> 60000L      // 最少 1 分钟
                        ttlMs > 86400000L -> 86400000L // 最多 24 小时
                        else -> ttlMs
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(LOG_TAG, "Failed to extract TTL from response: ${e.message}")
        }

        return 300000L // 默认 5 分钟
    }

    // 清理过期缓存条目
    private suspend fun cleanupExpiredCache() {
        dnsCacheMutex.withLock {
            val expiredKeys = dnsCache.entries
                .filter { it.value.isExpired() }
                .map { it.key }

            expiredKeys.forEach { dnsCache.remove(it) }

            // 如果缓存太大，删除最老的条目
            if (dnsCache.size > MAX_CACHE_SIZE) {
                val sortedEntries = dnsCache.entries
                    .sortedBy { it.value.timestamp }

                val toRemove = sortedEntries.size - MAX_CACHE_SIZE
                if (toRemove > 0) {
                    sortedEntries.take(toRemove).forEach {
                        dnsCache.remove(it.key)
                    }
                }
            }
        }
    }

    // 更新响应中的 Transaction ID
    private fun updateTransactionId(response: ByteArray, newId: Int): ByteArray {
        val updated = response.copyOf()
        updated[0] = ((newId shr 8) and 0xff).toByte()
        updated[1] = (newId and 0xff).toByte()
        return updated
    }

    // 归一化：去掉前导 "*." 或 "."，去掉尾部点，转小写
    private fun normalizeDomain(d: String): String =
        d.trim().trim('.').removePrefix("*.").removePrefix(".").lowercase()

    // 需要直连的域名（含 APNs/FCM/自管域等）
    private val bypassDomains = setOf(
        "conet.network",
        "silentpass.io",
        "openpgp.online",
        // Apple Push 相关
        "conet.network",
        "apple.com",
        "push.apple.com",
        "icloud.com",
        "push-apple.com.akadns.net",
        "silentpass.io",
        "courier.push.apple.com",
        "gateway.push.apple.com",
        "gateway.sandbox.push.apple.com",
        "gateway.icloud.com",
        "bag.itunes.apple.com",
        "init.itunes.apple.com",
        "xp.apple.com",
        "gsa.apple.com",
        "gsp-ssl.ls.apple.com",
        "gsp-ssl.ls-apple.com.akadns.net",
        "mesu.apple.com",
        "gdmf.apple.com",
        "deviceenrollment.apple.com",
        "mdmenrollment.apple.com",
        "iprofiles.apple.com",
        "ppq.apple.com",

        // 🔥 微信（WeChat）相关域名
        "wechat.com",
        "weixin.qq.com",
        "weixin110.qq.com",
        "tenpay.com",
        "mm.taobao.com",
        "wx.qq.com",
        "web.wechat.com",
        "webpush.weixin.qq.com",
        "qpic.cn",
        "qlogo.cn",
        "wx.gtimg.com",
        "minorshort.weixin.qq.com",
        "log.weixin.qq.com",
        "szshort.weixin.qq.com",
        "szminorshort.weixin.qq.com",
        "szextshort.weixin.qq.com",
        "hkshort.weixin.qq.com",
        "hkminorshort.weixin.qq.com",
        "hkextshort.weixin.qq.com",
        "hklong.weixin.qq.com",
        "sgshort.wechat.com",
        "sgminorshort.wechat.com",
        "sglong.wechat.com",
        "usshort.wechat.com",
        "usminorshort.wechat.com",
        "uslong.wechat.com",

        // 微信支付
        "pay.weixin.qq.com",
        "payapp.weixin.qq.com",

        // 微信文件传输
        "file.wx.qq.com",
        "support.weixin.qq.com",

        // 微信 CDN
        "mmbiz.qpic.cn",
        "mmbiz.qlogo.cn",
        "mmsns.qpic.cn",

        // 腾讯推送服务
        "dns.weixin.qq.com",
        "short.weixin.qq.com",
        "long.weixin.qq.com",
    )

    // 预处理一份"规范化后的"绕行域名集合（保持原 bypassDomains 不动）
    private val bypassNorm: Set<String> = bypassDomains.map { normalizeDomain(it) }.toSet()

    // 严格的"标签边界后缀匹配"
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

            // 设置 socket 选项以便更好地保护
            try {
                socket.tcpNoDelay = true
                socket.keepAlive = false
                socket.reuseAddress = false
            } catch (e: Exception) {
                Log.w(LOG_TAG, "Failed to set socket options: ${e.message}")
            }

            // 尝试保护 socket，带重试机制
            var protected = false
            var attempts = 0
            val maxAttempts = 5

            while (!protected && attempts < maxAttempts) {
                protected = Vpn2SocksService.protectSocket(socket)
                if (!protected) {
                    attempts++
                    if (attempts < maxAttempts) {
                        Log.w(LOG_TAG, "Socket protection attempt $attempts failed, retrying...")
                        Thread.sleep(100L * attempts) // 递增延迟
                    }
                }
            }

            if (!protected) {
                Log.e(LOG_TAG, "Failed to protect DNS socket after $maxAttempts attempts")
                // 可选：抛出异常阻止未保护的连接
                // throw IOException("Cannot create protected socket for DNS")
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

    // 在 DNSInterceptor 类中添加
    private val unprotectedQueries = AtomicInteger(0)
    private val protectedQueries = AtomicInteger(0)



    // 主查询方法：优先使用 DoH（带缓存）
    private suspend fun queryOverUpstreams(query: ByteArray): ByteArray? {
        // 首先尝试 DoH（内部会先检查缓存）
        val dohResult = queryViaDoH(query)
        if (dohResult != null) {
            Log.d(LOG_TAG, "DoH query successful (possibly from cache)")
            return dohResult
        }

        // DoH 失败，尝试 TCP DNS（作为备用）
        Log.w(LOG_TAG, "DoH failed, falling back to TCP DNS")
        return queryViaTraditionalTCP(query)
    }

    // DNS-over-HTTPS 实现（带缓存）
    private suspend fun queryViaDoH(query: ByteArray): ByteArray? {
        // 生成缓存键
        val cacheKey = generateCacheKey(query)

        // 提取原始查询的 Transaction ID
        val originalId = if (query.size >= 2) {
            ((query[0].toInt() and 0xff) shl 8) or (query[1].toInt() and 0xff)
        } else {
            0
        }

        // 先检查缓存
        dnsCacheMutex.withLock {
            dnsCache[cacheKey]?.let { entry ->
                if (!entry.isExpired()) {
                    Log.d(LOG_TAG, "DNS cache hit for query")
                    // 更新响应中的 Transaction ID 以匹配当前查询
                    return updateTransactionId(entry.response, originalId)
                } else {
                    // 删除过期条目
                    dnsCache.remove(cacheKey)
                    Log.d(LOG_TAG, "DNS cache expired, removing entry")
                }
            }
        }

        // 缓存未命中，执行实际的 DoH 查询
        Log.d(LOG_TAG, "DNS cache miss, performing DoH query")

        // 定期清理过期缓存
        if (dnsCache.size > MAX_CACHE_SIZE / 2) {
            cleanupExpiredCache()
        }

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

                val requestBody = query.toRequestBody("application/dns-message".toMediaType())

                val request = Request.Builder()
                    .url(provider)
                    .post(requestBody)
                    .addHeader("Accept", "application/dns-message")
                    .addHeader("Content-Type", "application/dns-message")
                    .build()

                val response = httpClient.newCall(request).execute()
                if (response.isSuccessful) {
                    protectedQueries.incrementAndGet()
                    val responseBytes = response.body?.bytes()
                    response.close()
                    if (responseBytes != null) {
                        Log.d(LOG_TAG, "DoH POST successful from $provider")

                        // 将响应存入缓存
                        val ttl = extractTTLFromResponse(responseBytes)
                        dnsCacheMutex.withLock {
                            dnsCache[cacheKey] = DNSCacheEntry(
                                response = responseBytes,
                                timestamp = System.currentTimeMillis(),
                                ttl = ttl
                            )
                            Log.d(LOG_TAG, "Cached DNS response with TTL: ${ttl}ms")
                        }

                        return responseBytes
                    }
                } else {
                    unprotectedQueries.incrementAndGet()
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
                    val responseBytes = response.body?.bytes()
                    response.close()
                    if (responseBytes != null) {
                        Log.d(LOG_TAG, "DoH GET successful from $provider")

                        // 将响应存入缓存
                        val ttl = extractTTLFromResponse(responseBytes)
                        dnsCacheMutex.withLock {
                            dnsCache[cacheKey] = DNSCacheEntry(
                                response = responseBytes,
                                timestamp = System.currentTimeMillis(),
                                ttl = ttl
                            )
                            Log.d(LOG_TAG, "Cached DNS response with TTL: ${ttl}ms")
                        }

                        return responseBytes
                    }
                } else {
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

    private val mutex = Mutex()

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
        if (!initialized) {
            // 最多等 500ms，一次性闸门 + 告警节流
            val ok = awaitReady(500)
            if (!ok && !initialized) throttledInitWarn("DNSInterceptor not yet initialized; gating DNS up to 500ms")
        }

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