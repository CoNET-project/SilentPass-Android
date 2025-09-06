package com.silentPass.vpn.vpn2socks

import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.SocketFactory
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class DNSInterceptor private constructor() {

	companion object {

        fun getInstance(): DNSInterceptor {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: DNSInterceptor().also {
                    INSTANCE = it
                    Log.d("DNSInterceptor", "Created singleton instance")
                }
            }
        }


        @Volatile
        private var INSTANCE: DNSInterceptor? = null
        private val initGate = java.util.concurrent.CountDownLatch(1)
        private val initDone = java.util.concurrent.atomic.AtomicBoolean(false)
        private val lastInitWarnAt = java.util.concurrent.atomic.AtomicLong(0L)

        fun signalReady() {
            if (initDone.compareAndSet(false, true)) initGate.countDown()
        }

        fun awaitReady(timeoutMs: Long): Boolean {
            if (initDone.get()) return true
            return try {
                initGate.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                false
            }
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
    private val bypassCache = ConcurrentHashMap<String, Boolean>()

    // DNS 查询缓存相关
    // Enhanced DNS cache with HTTP/2 support
    data class DNSCacheEntry(
        val response: ByteArray,
        val timestamp: Long,
        val ttl: Long = 300000L,
        val hits: AtomicLong = AtomicLong(0)
    ) {
        fun isExpired(): Boolean {
            return System.currentTimeMillis() - timestamp > ttl
        }
    }




    private val dnsCache = ConcurrentHashMap<String, DNSCacheEntry>()
    private val dnsCacheMutex = Mutex()
    private val MAX_CACHE_SIZE = 1000

    // DNS query channel for batch processing
    data class DnsQuery(
        val query: ByteArray,
        val callback: CompletableDeferred<ByteArray?>
    )

    private val queryChannel = Channel<DnsQuery>(Channel.UNLIMITED)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // HTTP/2 connection pool configuration
    private val connectionPool = ConnectionPool(
        maxIdleConnections = 5,
        keepAliveDuration = 5L,
        TimeUnit.MINUTES
    )

    // Enhanced OkHttp client with HTTP/2 support
    private val httpClient = OkHttpClient.Builder()
        .connectionPool(connectionPool)
        .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .writeTimeout(5, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .followRedirects(false)
        .socketFactory(ProtectedSocketFactory())
        .build()

    init {
        val instanceId = System.identityHashCode(this)
        Log.d(LOG_TAG, "DNSInterceptor instance created: $instanceId")

        // Start worker coroutines for parallel processing
        repeat(10) {
            scope.launch {
                processQueries()
            }
        }

        // Warmup connections
        scope.launch {
            warmupConnections()
        }

        // Mark as initialized
        initialized = true
        signalReady()

        // Verify socket protection
        Thread {
            Thread.sleep(500)
            try {
                val testSocket = Socket()
                val protected = Vpn2SocksService.protectSocket(testSocket)
                testSocket.close()
                Log.d(LOG_TAG, "Socket protection ${if (protected) "verified" else "not available"}")
            } catch (e: Exception) {
                Log.d(LOG_TAG, "Socket protection check failed: ${e.message}")
            }
        }.start()
    }

    // Process DNS queries from channel
    private suspend fun processQueries() {
        for (query in queryChannel) {
            try {
                val result = performDoHQuery(query.query)
                query.callback.complete(result)
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Query failed: ${e.message}")
                query.callback.complete(null)
            }
        }
    }

    // Warmup HTTP/2 connections
    private suspend fun warmupConnections() {
        val providers = listOf(
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query"
        )

        providers.forEach { provider ->
            scope.launch {
                try {
                    val testQuery = createDnsQuery("example.com")
                    performDoHQuery(testQuery)
                    Log.d(LOG_TAG, "Warmed up connection to $provider")
                } catch (e: Exception) {
                    Log.d(LOG_TAG, "Warmup failed for $provider")
                }
            }
        }
    }

    // Enhanced DoH query with HTTP/2 multiplexing
    private suspend fun performDoHQuery(query: ByteArray): ByteArray? {
        val cacheKey = generateCacheKey(query)
        val originalId = if (query.size >= 2) {
            ((query[0].toInt() and 0xff) shl 8) or (query[1].toInt() and 0xff)
        } else {
            0
        }

        // Check cache first
        dnsCacheMutex.withLock {
            dnsCache[cacheKey]?.let { entry ->
                if (!entry.isExpired()) {
                    entry.hits.incrementAndGet()
                    Log.d(LOG_TAG, "DNS cache hit (hits: ${entry.hits.get()})")
                    return updateTransactionId(entry.response, originalId)
                } else {
                    dnsCache.remove(cacheKey)
                }
            }
        }

        // Clean cache if needed
        if (dnsCache.size > MAX_CACHE_SIZE / 2) {
            cleanupExpiredCache()
        }

        // Try DoH providers
        val providers = listOf(
            "https://1.1.1.1/dns-query",
            "https://cloudflare-dns.com/dns-query",
            "https://8.8.8.8/dns-query",
            "https://dns.google/dns-query"
        )

        for (provider in providers) {
            try {
                val requestBody = query.toRequestBody("application/dns-message".toMediaType())
                val request = Request.Builder()
                    .url(provider)
                    .post(requestBody)
                    .addHeader("Accept", "application/dns-message")
                    .addHeader("Content-Type", "application/dns-message")
                    .build()

                httpClient.newCall(request).execute().use { response ->
                    if (response.isSuccessful) {
                        val responseBytes = response.body?.bytes()
                        if (responseBytes != null) {
                            Log.d(LOG_TAG, "DoH successful from $provider")

                            // Cache the response
                            val ttl = extractTTLFromResponse(responseBytes)
                            dnsCacheMutex.withLock {
                                dnsCache[cacheKey] = DNSCacheEntry(
                                    response = responseBytes,
                                    timestamp = System.currentTimeMillis(),
                                    ttl = ttl
                                )
                            }

                            return responseBytes
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "DoH error for $provider: ${e.message}")
            }
        }

        return null
    }

    // Batch DNS prefetch for common domains
    fun prefetchDomains(domains: List<String>) {
        scope.launch {
            domains.chunked(5).forEach { batch ->
                batch.map { domain ->
                    async {
                        try {
                            val query = createDnsQuery(domain)
                            val deferred = CompletableDeferred<ByteArray?>()
                            queryChannel.send(DnsQuery(query, deferred))
                            deferred.await()
                            Log.d(LOG_TAG, "Prefetched: $domain")
                        } catch (e: Exception) {
                            Log.d(LOG_TAG, "Prefetch failed: $domain")
                        }
                    }
                }.awaitAll()
            }
        }
    }



    // Main query handler with optimizations
    private suspend fun queryOverUpstreams(query: ByteArray): ByteArray? {
        // Use channel for batching
        val deferred = CompletableDeferred<ByteArray?>()
        queryChannel.send(DnsQuery(query, deferred))

        val result = withTimeoutOrNull(5000) {
            deferred.await()
        }

        if (result != null) {
            return result
        }

        // Fallback to TCP DNS
        Log.w(LOG_TAG, "DoH failed, falling back to TCP DNS")
        return queryViaTraditionalTCP(query)
    }

    // Cleanup expired cache with LRU eviction
    private suspend fun cleanupExpiredCache() {
        dnsCacheMutex.withLock {
            // Remove expired entries
            val expired = dnsCache.entries.filter { it.value.isExpired() }
            expired.forEach { dnsCache.remove(it.key) }

            // LRU eviction if still too large
            if (dnsCache.size > MAX_CACHE_SIZE) {
                val sorted = dnsCache.entries
                    .sortedBy { it.value.hits.get() }
                    .take(100)

                sorted.forEach { dnsCache.remove(it.key) }
                Log.d(LOG_TAG, "Evicted ${sorted.size} least-used cache entries")
            }
        }
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



    // 广告域名的正则模式
    private val adBlockPatterns = listOf(
        Regex(""".*\.(doubleclick|googleadservices|googlesyndication|google-analytics|adsrvr|adnxs|pubmatic|criteo|casalemedia|openx|rubiconproject|taboola|outbrain|scorecardresearch|quantserve|demdex|krxd)\..*"""),
        Regex("""^ad[sxvmn]?\d*[.-].*"""),
        Regex("""^.*[.-]ad[sxvmn]?\d*[.-].*"""),
        Regex("""^banner[sz]?[.-].*"""),
        Regex("""^.*[.-]banner[sz]?[.-].*"""),
        Regex("""^track(er|ing)?[.-].*"""),
        Regex("""^.*[.-]track(er|ing)?[.-].*"""),
        Regex("""^stat[sz]?[.-].*"""),
        Regex("""^.*[.-]stat[sz]?[.-].*"""),
        Regex("""^analytics?[.-].*"""),
        Regex("""^.*[.-]analytics?[.-].*"""),
        Regex("""^metric[sz]?[.-].*"""),
        Regex("""^.*[.-]metric[sz]?[.-].*"""),
        Regex("""^telemetry[.-].*"""),
        Regex("""^.*[.-]telemetry[.-].*"""),
        Regex("""^pixel[.-].*"""),
        Regex("""^.*[.-]pixel[.-].*"""),
        Regex("""^click[.-].*"""),
        Regex("""^.*[.-]click[.-].*"""),
        Regex("""^counter[.-].*"""),
        Regex("""^.*[.-]counter[.-].*"""),
        Regex("""^beacon[.-].*"""),
        Regex("""^.*[.-]beacon[.-].*""")
    )

    // 广告和跟踪域名黑名单
    private val adBlockDomains = setOf(
        // Google Ads
        "doubleclick.net",
        "googleadservices.com",
        "googlesyndication.com",
        "googletagmanager.com",
        "googletagservices.com",
        "google-analytics.com",
        "googleanalytics.com",
        "adsystem.com",
        "adsrvr.org",

        // Facebook/Meta
        "facebook-analytics.com",
        "fbcdn.net",

        // Amazon
        "amazon-adsystem.com",
        "amazontrust.com",

        // Microsoft
        "adsrvr.org",
        "bing.com",
        "msftconnecttest.com",

        // 通用广告网络
        "adsrvr.org",
        "adnxs.com",
        "adzerk.net",
        "pubmatic.com",
        "criteo.com",
        "criteo.net",
        "casalemedia.com",
        "openx.net",
        "rubiconproject.com",
        "serving-sys.com",
        "taboola.com",
        "outbrain.com",
        "media.net",
        "yieldmo.com",
        "3lift.com",
        "indexexchange.com",
        "sovrn.com",
        "sharethrough.com",
        "spotx.tv",
        "springserve.com",
        "tremor.io",
        "tribalfusion.com",
        "undertone.com",
        "yieldlab.net",
        "yieldmanager.com",
        "zedo.com",
        "zemanta.com",

        // 分析和跟踪
        "scorecardresearch.com",
        "quantserve.com",
        "imrworldwide.com",
        "nielsen.com",
        "alexa.com",
        "hotjar.com",
        "mouseflow.com",
        "luckyorange.com",
        "clicktale.com",
        "demdex.net",
        "krxd.net",
        "bluekai.com",
        "exelator.com",
        "mathtag.com",
        "turn.com",
        "acuityplatform.com",
        "adform.net",
        "bidswitch.net",
        "contextweb.com",
        "districtm.io",
        "emxdgt.com",
        "gumgum.com",
        "improve-digital.com",
        "inmobi.com",
        "loopme.com",
        "mobfox.com",
        "nexage.com",
        "rhythmone.com",
        "smaato.com",
        "smartadserver.com",
        "stroeer.io",
        "teads.tv",
        "triplelift.com",
        "verizonmedia.com",
        "vertamedia.com",
        "video.io",
        "viralize.com",
        "weborama.com",
        "widespace.com",

        // 中国广告网络
        "baidu.com",
        "tanx.com",
        "mediav.com",
        "admaster.com.cn",
        "dsp.com",
        "vamaker.com",
        "allyes.com",
        "ipinyou.com",
        "irs01.com",
        "istreamsche.com",
        "jusha.com",
        "knet.cn",
        "madserving.com",
        "miaozhen.com",
        "mmstat.com",
        "moad.cn",
        "mobaders.com",
        "mydas.mobi",
        "n.shifen.com",
        "netease.gg",
        "newrelic.com",
        "nexac.com",
        "ntalker.com",
        "nylalobghyhirgh.com",
        "o2omobi.com",
        "oimagea2.ydstatic.com",
        "optaim.com",
        "optimix.asia",
        "optimizely.com",
        "overture.com",
        "p0y.cn",
        "pagead.l.google.com",
        "pageadimg.l.google.com",
        "pbcdn.com",
        "pingdom.net",
        "pixanalytics.com",
        "ppjia55.com",
        "punchbox.org",
        "qchannel01.cn",
        "qiyou.com",
        "qtmojo.com",
        "quantcount.com",

        // 恶意软件和垃圾邮件
        "2o7.net",
        "omtrdc.net",
        "everesttech.net",
        "everest-tech.net",
        "rubiconproject.com",
        "adsafeprotected.com",
        "adsymptotic.com",
        "adtechjp.com",
        "advertising.com",
        "evidon.com",
        "voicefive.com",
        "buysellads.com",
        "carbonads.com",
        "cdn.ampproject.org",

        // 更多跟踪器
        "mixpanel.com",
        "kissmetrics.com",
        "segment.com",
        "segment.io",
        "keen.io",
        "amplitude.com",
        "appsflyer.com",
        "branch.io",
        "adjust.com",
        "kochava.com",
        "tenjin.io",
        "singular.net",
        "apptentive.com",
        "appboy.com",
        "braze.com",
        "customer.io",
        "intercom.io",
        "drift.com",
        "zendesk.com"
    )

    // 预处理黑名单（规范化）
    private val adBlockNorm: Set<String> = adBlockDomains.map { normalizeDomain(it) }.toSet()

    // 检查是否为广告域名
    private fun isAdDomain(domain: String): Boolean {
        val d = normalizeDomain(domain)

        // 缓存检查（复用 bypassCache 的逻辑）
        val cacheKey = "ad:$d"
        bypassCache[cacheKey]?.let { return it }

        // 精确匹配
        if (adBlockNorm.contains(d)) {
            bypassCache[cacheKey] = true
            return true
        }

        // 检查是否为子域名
        for (adDomain in adBlockNorm) {
            if (isSubdomainOf(d, adDomain)) {
                bypassCache[cacheKey] = true
                return true
            }
        }

        // 正则模式匹配
        val matched = adBlockPatterns.any { pattern ->
            pattern.matches(d)
        }

        bypassCache[cacheKey] = matched
        return matched
    }

    // 构建 NXDOMAIN 响应
    private fun buildNXDomainResponse(id: Int, query: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()

        // Header
        out.write(byteArrayOf((id shr 8).toByte(), (id and 0xff).toByte()))

        // Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCODE=3 (NXDOMAIN)
        val rd = (query[2].toInt() and 0x01)
        val flHigh = 0x81 or (rd shl 0)  // QR=1, OPCODE=0, AA=1, TC=0, RD
        val flLow = 0x83  // RA=1, Z=0, RCODE=3 (NXDOMAIN)
        out.write(byteArrayOf(flHigh.toByte(), flLow.toByte()))

        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        out.write(byteArrayOf(0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))

        // Copy original question section
        out.write(query, 12, query.size - 12)

        return out.toByteArray()
    }

    // 构建 0.0.0.0 响应（可选方案）
    private fun buildZeroResponse(id: Int, query: ByteArray, qname: String): ByteArray {
        return buildAResponse(
            id = id,
            query = query,
            qname = qname,
            ip = byteArrayOf(0, 0, 0, 0),  // 0.0.0.0
            ttl = 86400  // 24 hours
        )
    }


    // 需要直连的域名（含 APNs/FCM/自管域等）
    private val bypassDomains = setOf(
        "conet.network",
        "silentpass.io",
        "openpgp.online",
        "comm100vue.com",
        "comm100.io",

    )

    private val bypassPatterns = listOf(
        Regex(""".*\.doubleclick\.net$"""),
        Regex(""".*\.pubmatic\.com$"""),
        Regex(""".*\.criteo\.com$"""),
        Regex(""".*\.yahoo\.com$"""),
        Regex(""".*\.adsrvr\.org$""")
    )

// 增加预取和批处理 ·       1   `
    private suspend fun prefetchDNS(domains: List<String>) {
        kotlinx.coroutines.coroutineScope {
            domains.chunked(5).forEach { batch ->
                launch {
                    batch.forEach { domain ->
                        val cacheKey = generateCacheKeyForDomain(domain)
                        dnsCacheMutex.withLock {
                            if (!dnsCache.containsKey(cacheKey)) {
                                // 创建A记录查询
                                val query = createDnsQuery(domain)
                                queryViaDoH(query)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun generateCacheKeyForDomain(domain: String): String {
        // 为域名生成固定的缓存键
        return "A:$domain"
    }

    private fun createDnsQuery(domain: String): ByteArray {
        val out = ByteArrayOutputStream()
        // Transaction ID
        out.write(byteArrayOf(0x12, 0x34))
        // Flags: Standard query
        out.write(byteArrayOf(0x01, 0x00))
        // Questions: 1, Answers: 0, Authority: 0, Additional: 0
        out.write(byteArrayOf(0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))

        // Write domain name
        domain.split('.').forEach { label ->
            out.write(label.length.toByte().toInt())
            out.write(label.toByteArray())
        }
        out.write(0) // End of name

        // Type A (1), Class IN (1)
        out.write(byteArrayOf(0x00, 0x01, 0x00, 0x01))

        return out.toByteArray()
    }

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



    // 自定义 SocketFactory 确保 socket 被保护
    inner class ProtectedSocketFactory : SocketFactory() {
        override fun createSocket(): Socket {
            val socket = SocketPool.acquire()  // 使用池

            try {
                socket.tcpNoDelay = true
                socket.keepAlive = false
                socket.reuseAddress = false

                var protected = false
                var attempts = 0
                while (!protected && attempts < 3) {  // 减少重试次数
                    protected = Vpn2SocksService.protectSocket(socket)
                    if (!protected) {
                        attempts++
                        Thread.sleep(50L * attempts)
                    }
                }

                if (!protected) {
                    SocketPool.release(socket)  // 失败时归还
                    throw java.io.IOException("Cannot protect socket")  // 修正：添加java.io.
                }

                return socket
            } catch (e: Exception) {
                SocketPool.release(socket)  // 异常时归还
                throw e
            }
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

                httpClient.newCall(request).execute().use { response ->
					if (response.isSuccessful) {
						protectedQueries.incrementAndGet()
						val responseBytes = response.body?.bytes()
						
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

        // 缓存检查
        bypassCache[d]?.let { return it }

        // 精确匹配
        if (bypassNorm.contains(d)) {
            bypassCache[d] = true
            return true
        }

        // 模式匹配
        val matched = bypassPatterns.any { pattern ->
            pattern.matches(d)
        }

        bypassCache[d] = matched
        return matched
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

        // 检查是否为广告域名 - 新增
        if (isAdDomain(name)) {
            Log.d(LOG_TAG, "Blocked ad domain: $name")
            // 可以选择返回 NXDOMAIN 或 0.0.0.0
            // 选项 1: NXDOMAIN（域名不存在）
//            val response = buildNXDomainResponse(id, query)
            // 选项 2: 0.0.0.0（黑洞地址）
            val response = buildZeroResponse(id, query, name)
            return response to null
        }

        // 检查是否需要绕过（直连）
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
                            ipToDomain[it.raw] = d
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

    // Add proper cleanup
    fun close() {
        scope.cancel()
        httpClient.dispatcher.executorService.shutdown()
        httpClient.connectionPool.evictAll()
    }
}