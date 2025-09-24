package com.silentPass.vpn

import android.R
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import java.io.*
import java.net.*
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.Selector
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import java.nio.channels.ServerSocketChannel
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong



class SocketServerService : Service() {



	private fun connectWithChannel(host: String, port: Int): Socket? {
		return try {
			val channel = SocketChannel.open()
			channel.connect(InetSocketAddress(host, port))
			channel.socket()  // 这样创建的Socket才有channel
		} catch (e: Exception) {
			null
		}
	}


    // ====== Server State ======
    private var serverThread: Thread? = null
    @Volatile private var isRunning = true
    private var layerMinus: LayerMinus? = null
    private var serverChannel: ServerSocketChannel? = null
    private val LOG_TAG = "SocketServerService"

    // ====== ThreadPool (avoid per-conn thread explosion) ======
    private val threadCounter = AtomicInteger(0)
    private val threadPoolExecutor = ThreadPoolExecutor(
        50, 500, 30L, TimeUnit.SECONDS,
        SynchronousQueue<Runnable>(),
        ThreadFactory { r ->
            Thread(r).apply {
                name = "ProxyWorker-${threadCounter.incrementAndGet()}"
                isDaemon = true
                priority = Thread.NORM_PRIORITY
            }
        },
        ThreadPoolExecutor.CallerRunsPolicy()
    ).apply {
        // 核心线程也允许在空闲 keepAlive 后回收：高峰过后自动收缩
        allowCoreThreadTimeOut(true)
        prestartAllCoreThreads() // 预热核心线程，降低冷启动抖动
    }

    // 自适应微等待 prime：每轮最多阻塞 stepMs（默认5ms），若没数据则再等一轮，最多 maxRounds 轮；合并到 maxBytes（默认16KiB）
    private fun capturePrimeAdaptive(
        cliIn: BufferedInputStream,
        client: Socket,
        stepMs: Int = 5,      // 第2轮开始的步长
        maxRounds: Int = 3,    // 总轮数
        maxBytes: Int = 16 * 1024
    ): ByteArray? {
        val buf = ByteArray(maxBytes)
        var total = 0
        val prev = client.soTimeout
        val TLS_Length = 384

        try {
            // 0ms：非阻塞检查
            val immediate = cliIn.available()
            if (immediate > 0) {
                total = cliIn.read(buf, 0, minOf(immediate, maxBytes))
                if (total >= TLS_Length) {
                    return buf.copyOf(total)
                }
            }

            // 渐进式等待
            for (round in 0 until maxRounds) {
                if (total >= maxBytes) break

                // 关键：第一轮10ms，后续5ms
                val currentStepMs = if (round == 0) 10 else stepMs
                client.soTimeout = currentStepMs

                try {
                    val n = cliIn.read(buf, total, maxBytes - total)
                    if (n > 0) {
                        total += n
                        // 贪婪读取（限制次数）
                        var attempts = 0
                        while (attempts < 3 && cliIn.available() > 0 && total < maxBytes) {
                            val extra = cliIn.read(buf, total,
                                minOf(cliIn.available(), maxBytes - total, 4096))
                            if (extra <= 0) break
                            total += extra
                            attempts++
                        }

                        if (total >= TLS_Length) break
                    }
                } catch (_: SocketTimeoutException) {
                    if (total > TLS_Length - 100) break  // 有部分数据就返回
                }
            }
        } finally {
            client.soTimeout = prev
            recordPrime(total)
        }

        return if (total > 0) buf.copyOf(total) else null
    }

    // 仅在给定预算内合并已到达的首包；超时立即返回；LM/DIRECT 共用
    private fun capturePrimeWithBudget(
        cliIn: BufferedInputStream,
        client: Socket,
        budgetMs: Int = 20,
        maxBytes: Int = 16 * 1024
    ): ByteArray? {
        var total = 0
        val buf = ByteArray(maxBytes)
        val prev = client.soTimeout
        try {
            client.soTimeout = budgetMs
            while (total < maxBytes) {
                val n = try { cliIn.read(buf, total, maxBytes - total) }
                catch (_: java.net.SocketTimeoutException) { break }
                if (n <= 0) break
                total += n
                if (cliIn.available() == 0) break
            }
        } catch (_: Exception) {
            // 忽略 prime 异常
        } finally {
            try { client.soTimeout = prev } catch (_: Exception) {}
            try { recordPrime(total) } catch (_: Exception) {}
        }
        return if (total > 0) buf.copyOf(total) else null
    }

    // ====== Event-style metrics (print only on connection OPEN/CLOSE) ======
    private val activeConns = AtomicInteger(0)
    private val connSeq = AtomicLong(0)
    private fun logPoolSnapshot(event: String, connId: Long, note: String = "") {
        val q = threadPoolExecutor.queue
        val a = primeAttempts.get()
        val h = primeHits.get()
        val rate = if (a > 0) (h * 100 / a) else 0
        val avgB = if (h > 0) (primeBytesSum.get() / h) else 0
        Log.i(
            LOG_TAG,
            "[$event] conn#$connId " +
                    "activeConns=${activeConns.get()} " +
                    "pool={active:${threadPoolExecutor.activeCount}, size:${threadPoolExecutor.poolSize}/${threadPoolExecutor.maximumPoolSize}, largest:${threadPoolExecutor.largestPoolSize}} " +
                    "tasks={submitted:${threadPoolExecutor.taskCount}, completed:${threadPoolExecutor.completedTaskCount}} " +
                    "queue.size=${q.size} prime={hit:$h/att:$a, rate:${rate}%, avgB:$avgB} $note"
        )
    }
    private fun onConnOpen(connId: Long)  { activeConns.incrementAndGet(); logPoolSnapshot("OPEN",  connId) }
    private fun onConnClose(connId: Long) { if (activeConns.decrementAndGet() < 0) activeConns.set(0); logPoolSnapshot("CLOSE", connId) }

    // ====== High-throughput forwarder (NIO Channels + Direct ByteBuffer) ======
    // - Natural backpressure: write blocks when socket send buffer is full
    // - Adaptive flush: small-flow (e.g., TLS ClientHello) flush eagerly; bulk-flow flush in batches

    private fun forwardTrafficAsync(
        input: InputStream,
        output: OutputStream,
        bufferSize: Int = 128 * 1024,
        onDone: (() -> Unit)? = null,
        onEof: (() -> Unit)? = null,
		minBytesBeforeEofCallback: Long = 0,
		srcSocket: java.net.Socket? = null,
		dstSocket: java.net.Socket? = null
    ): Future<*> {
		return threadPoolExecutor.submit {


            val startNs = System.nanoTime()

			// 统一回退实现（阻塞流式），Selector 双向桥接在 bridgeWithSelector 调用处触发
			Log.d(LOG_TAG, "Start forwardTrafficAsync (fallback) from ${input.javaClass.simpleName} to ${output.javaClass.simpleName}")
			var src: java.nio.channels.ReadableByteChannel? = null
			var dst: java.nio.channels.WritableByteChannel? = null
            var totalBytes = 0L
			try {

				Log.d(LOG_TAG, "input available bytes: ${input.available()}")
				src = Channels.newChannel(input)
				dst = Channels.newChannel(output)
				val buf = java.nio.ByteBuffer.allocateDirect(bufferSize)
				var sinceLastFlush = 0L
				val WARMUP_LIMIT = 64 * 1024
				val FLUSH_THRESHOLD = 64 * 1024
				while (true) {
					val nRead = try { src.read(buf) }
					catch (_: SocketTimeoutException) {
						if (output is BufferedOutputStream) { try { output.flush() } catch (_: Exception) {} }
						continue
					} catch (_: java.nio.channels.ClosedByInterruptException) { break }
					catch (_: java.nio.channels.AsynchronousCloseException) { break }
					if (nRead == -1) {
						Log.d(LOG_TAG, "EOF reached after forwarding $totalBytes bytes")
						try { (output as? BufferedOutputStream)?.flush() } catch (_: Exception) {}
						if (totalBytes >= minBytesBeforeEofCallback) {
							try { onEof?.invoke() } catch (_: Exception) {}
						} else {
							Log.d(LOG_TAG, "Skip half-close: forwarded=$totalBytes < $minBytesBeforeEofCallback")
						}
						break
					}
					if (nRead == 0) continue
					totalBytes += nRead
					buf.flip()
					var wroteThisChunk = 0
					while (buf.hasRemaining()) {
						val nWritten = try { dst.write(buf) }
						catch (_: java.nio.channels.ClosedChannelException) {
							Log.d(LOG_TAG, "Output channel closed after $totalBytes bytes"); return@submit
						}
						if (nWritten == 0) Thread.yield()
						wroteThisChunk += nWritten
					}
					buf.compact()
					if (output is BufferedOutputStream) {
						sinceLastFlush += wroteThisChunk
						val inWarmup = totalBytes <= WARMUP_LIMIT
						val tinyChunk = wroteThisChunk in 1 until 32 * 1024
						if (inWarmup || sinceLastFlush >= FLUSH_THRESHOLD || tinyChunk) {
							try { output.flush() } catch (_: Exception) {}
							sinceLastFlush = 0
						}
					}
				}
			} catch (e: Exception) {
				Log.e(LOG_TAG, "Error forwarding traffic (fallback NIO)", e)
			} finally {
                val durMs = (System.nanoTime() - startNs) / 1_000_000
                Log.i(LOG_TAG, "FALLBACK stats bytes=$totalBytes dur=${durMs}ms")

				try { (output as? BufferedOutputStream)?.flush() } catch (_: Exception) {}
				try { onDone?.invoke() } catch (_: Exception) {}
			}
        }
    }


	// ===========================
	//  双向桥接（NIO Selector）
	// ===========================
	private fun bridgeWithSelector(
		clientCh: SocketChannel,
		upstreamCh: SocketChannel,
		onDone: (() -> Unit)? = null,
		onClientEof: (() -> Unit)? = null,
		onUpstreamEof: (() -> Unit)? = null,
		minClientBytesBeforeEof: Long = 32,
		minUpstreamBytesBeforeEof: Long = 0,
		firstDataToUpstream: ByteArray? = null,
		bufSize: Int = 128 * 1024,
        connId: Long = -1
	): Future<*> {
		return threadPoolExecutor.submit {

            fun isBenignIo(e: java.io.IOException): Boolean {
                val msg = e.message?.lowercase() ?: return false
                return msg.contains("connection reset by peer") || msg.contains("broken pipe")
            }

			var selector: Selector? = null
            var c2uBytes = 0L
            var u2cBytes = 0L
            var clientWriteClosed = false
            var upstreamWriteClosed = false
            var loggedClientWriteClosed = false
            var loggedUpstreamWriteClosed = false
            val startNs = System.nanoTime()

			try {
				clientCh.configureBlocking(false)
				upstreamCh.configureBlocking(false)
				selector = Selector.open()
				val cKey = clientCh.register(selector, SelectionKey.OP_READ)
				val uKey = upstreamCh.register(selector, SelectionKey.OP_READ)

				val c2u = java.nio.ByteBuffer.allocateDirect(bufSize)
				val u2c = java.nio.ByteBuffer.allocateDirect(bufSize)
				var cClosed = false
				var uClosed = false




				fun keyOpen(ch: SocketChannel?, key: SelectionKey?): Boolean =
					(ch != null && ch.isOpen && key != null && key.isValid)

				fun cancelKeyQuiet(key: SelectionKey?) {
					try { key?.cancel() } catch (_: Exception) {}
				}

				// 直连模式：把首包先注入上游
				if (firstDataToUpstream != null && firstDataToUpstream.isNotEmpty()) {
					c2u.put(firstDataToUpstream)
					c2u.flip()

					// 先尝试直接写入（写不动则注册一次 OP_WRITE 并暂停 client 读）
					try {
						while (c2u.hasRemaining()) {
							if (!keyOpen(upstreamCh, uKey)) break
							val n = upstreamCh.write(c2u)
							if (n == 0) {
								uKey.interestOps(uKey.interestOps() or SelectionKey.OP_WRITE)
								cKey.interestOps(cKey.interestOps() and SelectionKey.OP_READ.inv())
								break
							}
							c2uBytes += n
						}
					} catch (_: java.nio.channels.ClosedChannelException) {
						Log.d(LOG_TAG, "Selector: upstream closed while injecting firstData")
						uClosed = true
						cancelKeyQuiet(uKey)
						c2u.clear()
					}
					if (!c2u.hasRemaining()) { c2u.clear() } else { c2u.compact() }
				}

				val SELECT_TIMEOUT = 500L
				loop@ while (true) {
					selector.select(SELECT_TIMEOUT)
					val it = selector.selectedKeys().iterator()
					while (it.hasNext()) {
						val key = it.next(); it.remove()
						when (key.channel()) {
							clientCh -> {
								if (key.isReadable && !cClosed) {
									// 读 client → c2u
									if (!c2u.hasRemaining()) { // 背压：停读
										cKey.interestOps(cKey.interestOps() and SelectionKey.OP_READ.inv())
									} else {
										try {
                                            val n = try { clientCh.read(c2u) } catch (e: java.io.IOException) {
                                                if (isBenignIo(e)) -1 else throw e
                                            }
											if (n == -1) {
												cClosed = true
												cKey.interestOps(cKey.interestOps() and SelectionKey.OP_READ.inv())
												if (c2uBytes >= minClientBytesBeforeEof) {
													try { onClientEof?.invoke() } catch (_: Exception) {}
												} else {
													Log.d(LOG_TAG, "Skip half-close (client): forwarded=$c2uBytes < $minClientBytesBeforeEof")
												}
											} else if (n > 0) {
												c2uBytes += n
												// 触发上游可写
												uKey.interestOps(uKey.interestOps() or SelectionKey.OP_WRITE)
											}
										} catch (_: java.nio.channels.ClosedChannelException) {
											Log.d(LOG_TAG, "Selector: client closed on read")
											cClosed = true
											cancelKeyQuiet(cKey)
										}
									}
								}
								if (key.isWritable) {
									try {
										if (!keyOpen(clientCh, cKey)) { clientWriteClosed = true; cancelKeyQuiet(cKey) }
										u2c.flip()
										while (u2c.hasRemaining()) {
											val n = clientCh.write(u2c)
											if (n == 0) {
												// 保留一次 OP_WRITE，暂停上游读，等待可写
												key.interestOps(key.interestOps() or SelectionKey.OP_WRITE)
												uKey.interestOps(uKey.interestOps() and SelectionKey.OP_READ.inv())
												break
                                            }
                                        }
                                        u2c.compact()
                                        if (u2c.position() == 0) {
                                            key.interestOps(key.interestOps() and SelectionKey.OP_WRITE.inv())
                                            // 读上游可恢复
                                            uKey.interestOps(uKey.interestOps() or SelectionKey.OP_READ)
                                        }
                                    } catch (_: java.nio.channels.ClosedChannelException) {
                                        clientWriteClosed = true
                                        try { upstreamCh.socket().shutdownOutput() } catch (_: Exception) {}
                                        if (!loggedClientWriteClosed) {
                                            Log.d(LOG_TAG, "Selector: client closed on write")
                                            loggedClientWriteClosed = true
                                        }
                                        cancelKeyQuiet(cKey)
                                        u2c.clear()
                                    } catch (_: java.nio.channels.CancelledKeyException) {
                                        clientWriteClosed = true
                                        if (!loggedClientWriteClosed) {
                                            Log.d(LOG_TAG, "Selector: client key cancelled on write")
                                            loggedClientWriteClosed = true
                                        }
                                    } catch (e: java.io.IOException) {
                                        if (isBenignIo(e)) {
                                            clientWriteClosed = true
                                            try { upstreamCh.socket().shutdownOutput() } catch (_: Exception) {}
                                            if (!loggedClientWriteClosed) {
                                                Log.d(LOG_TAG, "Selector: client write benign IO (${e.message})")
                                                loggedClientWriteClosed = true
                                            }
                                            cancelKeyQuiet(cKey); u2c.clear()
                                        } else {
                                            throw e
                                        }
                                    }
								}
							}
							upstreamCh -> {
								if (key.isReadable && !uClosed) {
									// 读 upstream → u2c
									if (!u2c.hasRemaining()) {
										uKey.interestOps(uKey.interestOps() and SelectionKey.OP_READ.inv())
									} else {
										try {
                                            val n = try { upstreamCh.read(u2c) } catch (e: java.io.IOException) {
                                                if (isBenignIo(e)) -1 else throw e
                                            }

                                            if (n == -1) {
                                                uClosed = true
                                                uKey.interestOps(uKey.interestOps() and SelectionKey.OP_READ.inv())
                                                if (u2cBytes >= minUpstreamBytesBeforeEof) {
                                                    try { onUpstreamEof?.invoke() } catch (_: Exception) {}
                                                } else {
                                                    Log.d(LOG_TAG, "Skip half-close (upstream): forwarded=$u2cBytes < $minUpstreamBytesBeforeEof")
                                                }
                                            } else if (n > 0) {
                                                u2cBytes += n
                                                // 触发下游可写
                                                cKey.interestOps(cKey.interestOps() or SelectionKey.OP_WRITE)
                                            }
                                        } catch (_: java.nio.channels.ClosedChannelException) {
                                            Log.d(LOG_TAG, "Selector: upstream closed on read")
                                            uClosed = true
                                            cancelKeyQuiet(uKey)
                                        }
									}
								}
								if (key.isWritable) {
									// c2u 剩余 → upstream
									try {
                                        if (!keyOpen(upstreamCh, uKey)) { upstreamWriteClosed = true; cancelKeyQuiet(uKey) }
                                        c2u.flip()
                                        while (c2u.hasRemaining()) {
                                            val n = upstreamCh.write(c2u)
                                            if (n == 0) {
                                                key.interestOps(key.interestOps() or SelectionKey.OP_WRITE)
                                                cKey.interestOps(cKey.interestOps() and SelectionKey.OP_READ.inv())
                                                break
                                            }
                                        }
                                        c2u.compact()
                                        if (c2u.position() == 0) {
                                            key.interestOps(key.interestOps() and SelectionKey.OP_WRITE.inv())
                                            // 读 client 可恢复
                                            cKey.interestOps(cKey.interestOps() or SelectionKey.OP_READ)
                                        }
                                    } catch (_: java.nio.channels.ClosedChannelException) {
                                        upstreamWriteClosed = true
                                        try { clientCh.socket().shutdownOutput() } catch (_: Exception) {}
                                        if (!loggedUpstreamWriteClosed) {
                                            Log.d(LOG_TAG, "Selector: upstream closed on write")
                                            loggedUpstreamWriteClosed = true
                                        }
                                        cancelKeyQuiet(uKey); c2u.clear()
                                    } catch (_: java.nio.channels.CancelledKeyException) {

                                        upstreamWriteClosed = true
                                        if (!loggedUpstreamWriteClosed) {
                                            Log.d(LOG_TAG, "Selector: upstream key cancelled on write")
                                            loggedUpstreamWriteClosed = true
                                        }
                                    } catch (e: java.io.IOException) {
                                        if (isBenignIo(e)) {
                                            upstreamWriteClosed = true
                                            try { clientCh.socket().shutdownOutput() } catch (_: Exception) {}
                                            if (!loggedUpstreamWriteClosed) {
                                                Log.d(LOG_TAG, "Selector: upstream write benign IO (${e.message})")
                                                loggedUpstreamWriteClosed = true
                                            }
                                            cancelKeyQuiet(uKey); c2u.clear()
                                        } else {
                                            throw e
                                        }
                                    }
								}
							}
						}
					}

					// 退出条件：两端读都关 & 两个方向缓冲都清空（写侧也无 pending）
                    if ((cClosed || clientWriteClosed) &&
                        (uClosed || upstreamWriteClosed) &&
                        c2u.position() == 0 && u2c.position() == 0) break@loop
				}
			} catch (e: Exception) {
                // 可预期 I/O（RST / PIPE）降级为 DEBUG；其他保留堆栈
                if (e is java.io.IOException &&
                    ((e.message?.lowercase()?.contains("connection reset by peer") == true) ||
                            (e.message?.lowercase()?.contains("broken pipe") == true))) {
                    Log.d(LOG_TAG, "Selector bridge benign IO (${e.message})")
                } else {
                    Log.e(LOG_TAG, "Selector bridge error", e)
                }
			} finally {
                val durMs = (System.nanoTime() - startNs) / 1_000_000
                Log.i(LOG_TAG,
                    "Start bridgeWithSelector BRIDGE stats conn#$connId c2u=$c2uBytes u2c=$u2cBytes dur=${durMs}ms " +
                           "halfClose(client=$clientWriteClosed, upstream=$upstreamWriteClosed)"
                )
				try { selector?.close() } catch (_: Exception) {}
				try { onDone?.invoke() } catch (_: Exception) {}
			}
		}
	}

    // ====== Android Service lifecycle ======
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(1, createNotification()) // must start within 5s
        Log.d(LOG_TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent?.getStringExtra("VPN_DATA_B64")?.let { b64 ->
            try {
                val data = Base64.decode(b64, Base64.DEFAULT)
                val json = String(data, Charsets.UTF_8)
                val startVPNData = Gson().fromJson(json, StartVPNData::class.java)
                this.layerMinus = LayerMinus(startVPNData)

            } catch (e: Exception) {
                Log.e(LOG_TAG, "Failed to parse VPN data", e)
            }
        }
        if (serverThread == null || !serverThread!!.isAlive) startSocketServer()
        return START_STICKY
    }

    private fun startSocketServer() {
        serverThread = Thread {
            try {
                	serverChannel = ServerSocketChannel.open().apply {
						configureBlocking(true)
						bind(InetSocketAddress(8888), 256)
					}
				Log.d(LOG_TAG, "Server started on port 8888 (ServerSocketChannel)")

                while (isRunning) {
					val clientCh = serverChannel?.accept() ?: break

                    // 调优下游通道，避免主动 close() 触发 RST、提升交互性
                    tuneSocket(clientCh)

					val client = clientCh.socket()
					val connId = connSeq.incrementAndGet()
					onConnOpen(connId)
					// 把下游的 SocketChannel 一并传入，供 Selector 桥接使用

					threadPoolExecutor.execute { 
						handleClient(client, connId, clientCh)
					}
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Server error", e)
            } finally {
                try { serverChannel?.close() } catch (_: Exception) {}
            }
        }.apply { isDaemon = true }
        serverThread?.start()
    }

    override fun onDestroy() {
        isRunning = false
        try { serverChannel?.close() } catch (_: Exception) {}
        serverThread?.interrupt()
        super.onDestroy()
        Log.d(LOG_TAG, "onDestroy called")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // ====== Helpers ======
    private fun readFirstChunkOrNull(ins: InputStream): ByteArray? {
        val buf = ByteArray(4096)
        val n = try { ins.read(buf) } catch (_: Exception) { return null }
        return when {
            n > 0  -> buf.copyOf(n)
            n == 0 -> ByteArray(0)
            else   -> null
        }
    }

    private fun setSocketPerfOptions(a: Socket?, b: Socket?) {
        try {
            a?.tcpNoDelay = true
            a?.sendBufferSize = 256 * 1024
            a?.receiveBufferSize = 256 * 1024
            a?.soTimeout = 500   // 500ms 读超时，用于触发 idle flush
            b?.tcpNoDelay = true
            b?.sendBufferSize = 256 * 1024
            b?.receiveBufferSize = 256 * 1024
            b?.soTimeout = 500
        } catch (_: Exception) {}
    }

    // ====== Client dispatcher ======
    private fun handleClient(client: Socket, connId: Long, clientChOpt: SocketChannel? = null) {
        try {
			// 统一获取下游通道：优先从 client.getChannel()，否则回退到入参
			val clientChHere: SocketChannel? =
				(client.channel as? SocketChannel) ?: clientChOpt

            val input  = BufferedInputStream(client.getInputStream())
            val output = client.getOutputStream()
            input.mark(4096)
            val version = input.read()
            input.reset()

            when (version) {
                0x04 -> handleSocks4(client, input, output, connId, clientChHere)
                0x05 -> handleSocks5(client, input, output, connId, clientChHere)
                else -> {
                    // HTTP branch guard: only parse if first byte is ASCII uppercase (method)
                    input.mark(1)
                    val b0 = input.read()
                    input.reset()
                    if (b0 !in 65..90) {
                        Log.d(LOG_TAG, "HTTP guard: non-HTTP first byte=0x${String.format("%02x", b0)}; drop")
                        try { client.close() } catch (_: Exception) {}
                        onConnClose(connId); return
                    }

                    val reader = BufferedReader(InputStreamReader(input))
                    val requestLine = reader.readLine()
                    if (requestLine == null || !Regex("^[A-Z]{3,10} ").containsMatchIn(requestLine)) {
                        Log.d(LOG_TAG, "HTTP guard: invalid request line, drop: $requestLine")
                        try { client.close() } catch (_: Exception) {}
                        onConnClose(connId); return
                    }
                    Log.d(LOG_TAG, "HTTP/s forwarding $requestLine")
                    if (requestLine?.startsWith("CONNECT") == true) {
                        handleHttpsConnect(client, input, requestLine, connId, clientChHere)
                    } else {
                        handleHttpProxy(client, requestLine, reader, connId, clientChHere)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Error handling client", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }

    // ====== HTTP (non-CONNECT) ======
    private fun handleHttpProxy(client: Socket, requestLine: String?, reader: BufferedReader, connId: Long, clientChOpt: SocketChannel? = null) {
        if (requestLine == null) {
            Log.e(LOG_TAG, "Null request line")
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId); return
        }

        try {
            val headers = mutableListOf<String>()
            var line: String?
            while (reader.readLine().also { line = it } != null && line!!.isNotEmpty()) {
                headers.add(line!!)
            }

            val parts = requestLine.split(" ")
            if (parts.size < 3) {
                Log.e(LOG_TAG, "Invalid request line")
                try { client.close() } catch (_: Exception) {}
                onConnClose(connId); return
            }
            val method = parts[0]
            val fullUrl = parts[1]
            val httpVersion = parts[2]

            val url = URL(fullUrl)
            val host = url.host
            val port = if (url.port != -1) url.port else 80
            val path = url.file.ifEmpty { "/" }

            // Body (if any)
            var body: CharArray? = null
            val contentLength = headers.find { it.startsWith("Content-Length", ignoreCase = true) }
                ?.split(":")?.getOrNull(1)?.trim()?.toIntOrNull() ?: 0
            if (contentLength > 0) {
                body = CharArray(contentLength)
                reader.read(body)
            }

            // Rewrite: full URL -> path (strip Proxy-* headers)
            val sb = StringBuilder()
            sb.append("$method $path $httpVersion\r\n")
            for (h in headers) if (!h.startsWith("Proxy-", ignoreCase = true)) sb.append(h).append("\r\n")
            sb.append("\r\n")
            if (body != null) sb.append(String(body))
            val requestBody = sb.toString() // == firstData for HTTP
            val isLayerMinus = (layerMinus != null)
            Log.i(LOG_TAG, "HTTP proxy connect $host:$port via LayerMinus=$isLayerMinus")


            val upstream: Socket? = if (isLayerMinus) {
                // LayerMinus expects firstData packaged inside
                layerMinus?.connectToLayerMinus(host, port.toString(), requestBody.toByteArray(Charsets.UTF_8))
            } else {
                try {
                    val ch = SocketChannel.open(InetSocketAddress(host, port))
                    tuneSocket(ch)
                    ch.socket()
                } catch (e: Exception) {
					Log.e(LOG_TAG, "Failed to connect to $host:$port", e); null
                }
            }

			if (upstream == null) { client.close(); onConnClose(connId); return }
            setSocketPerfOptions(client, upstream)

            val clientChHere = clientChOpt
			val upstreamCh = upstream.channel as? SocketChannel
			val useSelector = (clientChHere != null && upstreamCh != null)


            // DIRECT must write firstData first, then start bidirectional pumps
            if (layerMinus == null) {
                BufferedWriter(OutputStreamWriter(upstream.getOutputStream())).apply {
                    write(requestBody); flush()
                }
            }

            val upIn  = BufferedInputStream(upstream.getInputStream(),   128 * 1024)
            val upOut = BufferedOutputStream(upstream.getOutputStream(), 128 * 1024)
            val cliIn  = BufferedInputStream(client.getInputStream(),    128 * 1024)
            val cliOut = BufferedOutputStream(client.getOutputStream(),  128 * 1024)

			val remaining = java.util.concurrent.atomic.AtomicInteger(2)
			val onBothDone = {
                if (remaining.decrementAndGet() == 0) {
                    try { cliOut.flush() } catch (_: Exception) {}
                    try { upOut.flush() } catch (_: Exception) {}
                    try { upstream.close() } catch (_: Exception) {}
                    try { client.close() }   catch (_: Exception) {}
                    onConnClose(connId)
                }
            }

			if (useSelector) {
				// HTTP 直连：请求头体你已在上游写入；主体后续走 Selector 桥接
				bridgeWithSelector(
					clientChHere!!, upstreamCh!!,
					onDone = {
						try { upstream.close() } catch (_: Exception) {}
						try { client.close() } catch (_: Exception) {}
						onConnClose(connId)
					},
					onClientEof = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
					onUpstreamEof = { try { client.shutdownOutput() } catch (_: Exception) {} },
					minClientBytesBeforeEof = 32,
                    connId = connId
				)
			} else {
				// 回退：保持原来的双泵
				forwardTrafficAsync(upIn,  cliOut, onDone = onBothDone, srcSocket = upstream, dstSocket = client)
				forwardTrafficAsync(
					cliIn, upOut,
					onDone = onBothDone,
					onEof  = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
					minBytesBeforeEofCallback = 1,
					srcSocket = client, dstSocket = upstream
				)
			}
        } catch (e: Exception) {
            Log.e(LOG_TAG, "HTTP proxy error", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }

    // ====== HTTPS (CONNECT) ======
    private fun handleHttpsConnect(client: Socket, input: BufferedInputStream, requestLine: String, connId: Long, clientChOpt: SocketChannel? = null) {
        try {
            val parts = requestLine.split(" ")
            val target = parts[1]
            val host = target.substringBefore(":")
            val port = target.substringAfter(":").toIntOrNull() ?: 443

            // Tell client the tunnel is ready
            BufferedWriter(OutputStreamWriter(client.getOutputStream())).apply {
                write("HTTP/1.1 200 Connection Established\r\n\r\n")
                flush()
            }

            // 统一：在分支前“微等待 prime”（≤10ms；复用同一个 BufferedInputStream）
            val cliIn = input
            val firstData = capturePrimeWithBudget(cliIn, client, maxBytes = 16 * 1024)


            val isLayerMinus = (layerMinus != null)
            Log.i(LOG_TAG, "HTTPS proxy connect $host:$port via LayerMinus=$isLayerMinus")


            val upstream: Socket? = if (isLayerMinus) {
                layerMinus?.connectToLayerMinus(host, port.toString(), firstData)
            } else {
                try {
                    val ch = SocketChannel.open(InetSocketAddress(host, port))
                    tuneSocket(ch)
                    ch.socket()
                } catch (e: Exception) {
                    Log.e(LOG_TAG, "Failed to connect to $host:$port", e); null
                }
            }


            if (upstream == null) {
                try { client.close() } catch (_: Exception) {}
                onConnClose(connId); return
            }

            setSocketPerfOptions(client, upstream)
			val clientChHere = clientChOpt
			val upstreamCh = upstream.channel as? SocketChannel
			val useSelector = (clientChHere != null && upstreamCh != null)


            val upIn   = BufferedInputStream(upstream.getInputStream(),   128 * 1024)
            val upOutB = BufferedOutputStream(upstream.getOutputStream(), 128 * 1024)
            val cliOut = BufferedOutputStream(client.getOutputStream(),   128 * 1024)
			
			// Selector 模式：由桥接函数在启动前注入 firstData；否则仍走原流程
			val directFirstData = if (layerMinus == null) firstData else null
			if (!useSelector && directFirstData != null && directFirstData.isNotEmpty()) {
				try { upOutB.write(directFirstData); upOutB.flush() } catch (_: Exception) {}
			}


            // 双泵复用同一个 cliIn；cli->up 方向保持 minBytesBeforeEofCallback=1
            val remaining = java.util.concurrent.atomic.AtomicInteger(2)
            val onBothDone = {
                if (remaining.decrementAndGet() == 0) {
                    try { cliOut.flush() } catch (_: Exception) {}
                    try { upOutB.flush() } catch (_: Exception) {}
                    try { upstream.close() } catch (_: Exception) {}
                    try { client.close() }   catch (_: Exception) {}
                    onConnClose(connId)
                }
            }
			if (useSelector) {
				// 修正：bridgeWithSelector只需要一次调用，不需要remaining计数
				bridgeWithSelector(
					clientChHere!!, upstreamCh!!,
					onDone = {
						try { upstream.close() } catch (_: Exception) {}
						try { client.close() } catch (_: Exception) {}
						onConnClose(connId)
					},
					onClientEof = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
					onUpstreamEof = { try { client.shutdownOutput() } catch (_: Exception) {} },
					minClientBytesBeforeEof = 32,
					firstDataToUpstream = directFirstData,
                    connId = connId

				)
			} else {
				forwardTrafficAsync(
					upIn, cliOut,
					onDone = onBothDone,
					onEof  = { try { client.shutdownOutput() } catch (_: Exception) {} },
					srcSocket = upstream, dstSocket = client
				)
				forwardTrafficAsync(
					cliIn, upOutB,
					onDone = onBothDone,
					onEof  = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
					minBytesBeforeEofCallback = 1,
					srcSocket = client, dstSocket = upstream
				)
			}
        } catch (e: Exception) {
            Log.e(LOG_TAG, "HTTPS CONNECT failed", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }

    /**
     * SOCKS4 错误响应码定义
     * 参考 RFC 1928 和 SOCKS4 协议规范
     */
    object Socks4ReplyCode {
        const val GRANTED = 0x5a           // 请求已批准，连接建立
        const val REJECTED = 0x5b          // 请求被拒绝或失败（通用错误）
        const val NO_IDENTD = 0x5c         // 请求失败，因为客户端没有运行 identd
        const val USER_MISMATCH = 0x5d     // 请求失败，因为 identd 报告的用户ID不匹配
    }

    /**
     * 发送 SOCKS4 拒绝响应
     *
     * @param output 输出流
     * @param replyCode 错误码（使用 Socks4ReplyCode 中定义的常量）
     * @param port 端口号（可选，用于回显）
     * @param ip IP地址（可选，用于回显）
     */
    private fun sendSocks4Reject(
        output: OutputStream,
        replyCode: Int,
        port: Int = 0,
        ip: ByteArray? = null
    ) {
        try {
            // SOCKS4 响应格式:
            // +----+----+----+----+----+----+----+----+
            // |VER | REP |  DSTPORT  |      DSTIP        |
            // +----+----+----+----+----+----+----+----+
            // | 0  |CODE|  2 bytes  |     4 bytes       |
            // +----+----+----+----+----+----+----+----+

            val response = ByteArray(8)

            // VER: 0x00 表示响应（不是 0x04）
            response[0] = 0x00

            // REP: 响应码
            response[1] = replyCode.toByte()

            // DSTPORT: 端口（网络字节序，big-endian）
            response[2] = (port shr 8).toByte()
            response[3] = (port and 0xFF).toByte()

            // DSTIP: IP地址（4字节）
            if (ip != null && ip.size == 4) {
                System.arraycopy(ip, 0, response, 4, 4)
            } else {
                // 默认使用 0.0.0.0
                response[4] = 0x00
                response[5] = 0x00
                response[6] = 0x00
                response[7] = 0x00
            }

            // 发送响应
            output.write(response)
            output.flush()

            // 记录日志
            val codeStr = when (replyCode) {
                Socks4ReplyCode.GRANTED -> "GRANTED"
                Socks4ReplyCode.REJECTED -> "REJECTED"
                Socks4ReplyCode.NO_IDENTD -> "NO_IDENTD"
                Socks4ReplyCode.USER_MISMATCH -> "USER_MISMATCH"
                else -> "UNKNOWN($replyCode)"
            }

            Log.d(LOG_TAG, "SOCKS4 响应: $codeStr, port=$port")

        } catch (e: Exception) {
            Log.e(LOG_TAG, "发送 SOCKS4 响应失败: ${e.message}", e)
        }
    }
    // ====== SOCKS4 ======
    // ====== SOCKS4 / SOCKS4a ======
    private fun handleSocks4(client: Socket, input: InputStream, output: OutputStream, connId: Long, clientChOpt: SocketChannel? = null) {
        try {
            // VER(0x04)
            val ver = input.read()
            if (ver != 0x04) {
                sendSocks4Reject(output, Socks4ReplyCode.REJECTED)
                client.close()
                onConnClose(connId)
                return
            }

            // CMD，仅支持 CONNECT(0x01)
            val cmd = input.read()
            if (cmd != 0x01) {
                sendSocks4Reject(output, Socks4ReplyCode.REJECTED)
                client.close()
                onConnClose(connId)
                return
            }

            // DSTPORT (network-order)
            val port = (input.read() shl 8) or input.read()
            // DSTIP
            if (port <= 0 || port > 65535) {
                sendSocks4Reject(output, Socks4ReplyCode.REJECTED)
                client.close()
                onConnClose(connId)
                return
            }
            val ip = ByteArray(4); input.read(ip)

            // USERID (NUL terminated)
            while (input.read() != 0) { /* discard */ }

            // SOCKS4a: ip=0.0.0.x 且 x!=0 时，后续还有域名（NUL 结尾）
            val isSocks4a = (ip[0].toInt() == 0 &&
                    ip[1].toInt() == 0 &&
                    ip[2].toInt() == 0 &&
                    ip[3].toInt() != 0)

            val destHost: String = if (isSocks4a) {
                // SOCKS4a：读取域名
                val sb = StringBuilder()
                var b: Int
                while (input.read().also { b = it } != 0 && b != -1) {
                    sb.append(b.toChar())
                }
                val domain = sb.toString()

                // 验证域名不为空
                if (domain.isEmpty()) {
                    Log.e(LOG_TAG, "SOCKS4a: 空域名")
                    sendSocks4Reject(output, Socks4ReplyCode.REJECTED)
                    client.close()
                    onConnClose(connId)
                    return
                }

                Log.d(LOG_TAG, "SOCKS4a 请求: $domain:$port")
                domain
            } else {
                // SOCKS4：IP地址字符串
                val ipStr = ip.joinToString(".") { (it.toInt() and 0xFF).toString() }

                // 验证IP地址合法性
                if (ipStr == "0.0.0.0" || ipStr == "255.255.255.255") {
                    Log.e(LOG_TAG, "SOCKS4: 无效IP $ipStr")
                    sendSocks4Reject(output, Socks4ReplyCode.REJECTED)
                    client.close()
                    onConnClose(connId)
                    return
                }

                Log.d(LOG_TAG, "SOCKS4 请求: $ipStr:$port")
                ipStr
            }

            // 立即发送granted响应（使用占位符地址）
            val granted = byteArrayOf(
                0x00, 0x5a,  // 成功
                0x00, 0x00,  // 端口占位
                0x00, 0x00, 0x00, 0x00  // IP占位
            )

            try {
                output.write(granted)
                output.flush()
            } catch (e: Exception) {
                Log.e(LOG_TAG, "发送SOCKS4响应失败", e)
                client.close()
                onConnClose(connId)
                return
            }


            // 捕获首包
            val cliIn = if (input is BufferedInputStream) input else BufferedInputStream(input, 128 * 1024)
            val firstData = capturePrimeWithBudget(cliIn, client)


            val isLayerMinus = (layerMinus != null)
            Log.i(LOG_TAG, "SOCKS v4 proxy connect $destHost:$port via LayerMinus=$isLayerMinus")

            val upstream: Socket? = if (isLayerMinus) {
                layerMinus?.connectToLayerMinus(destHost, port.toString(), firstData)
            } else {
                try {
                    val ch = SocketChannel.open(InetSocketAddress(destHost, port))
                    tuneSocket(ch)
                    ch.socket()
                } catch (e: Exception) {
                    Log.e(LOG_TAG, "Failed to connect to $destHost:$port", e); null
                }
            }


            if (upstream == null) {
                try { output.write(byteArrayOf(0x00, 0x5b, 0,0, 0,0,0,0)); output.flush() } catch (_: Exception) {}
                client.close(); onConnClose(connId); return
            }

            setSocketPerfOptions(client, upstream)





            val cliOut = BufferedOutputStream(output, 128 * 1024)

			val clientChHere = clientChOpt
			val upstreamCh = upstream.channel as? SocketChannel
			val useSelector = (clientChHere != null && upstreamCh != null)

            val upIn  = BufferedInputStream(upstream.getInputStream(),   128 * 1024)
            val upOut = BufferedOutputStream(upstream.getOutputStream(), 128 * 1024)
            // DIRECT：若抓到了首包，先踢给上游

			val directFirstData = if (layerMinus == null) firstData else null
			if (!useSelector && directFirstData != null && directFirstData.isNotEmpty()) {
				try { upOut.write(directFirstData); upOut.flush() } catch (_: Exception) {}
			}


            // 之后再启动双泵（保持你现有的 onEof→shutdownOutput、onDone 收尾）
            val remaining = java.util.concurrent.atomic.AtomicInteger(2)
            val onBothDone = {
                if (remaining.decrementAndGet() == 0) {
                    try { cliOut.flush() } catch (_: Exception) {}
                    try { upOut.flush() }  catch (_: Exception) {}
                    try { upstream.close() } catch (_: Exception) {}
                    try { client.close() }   catch (_: Exception) {}
                    onConnClose(connId)
                }
            }
			if (useSelector) {
				bridgeWithSelector(
					clientChHere!!, upstreamCh!!,
					onDone = {
						try { upstream.close() } catch (_: Exception) {}
						try { client.close() } catch (_: Exception) {}
						onConnClose(connId)
					},
					onClientEof = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
					onUpstreamEof = { try { client.shutdownOutput() } catch (_: Exception) {} },
					minClientBytesBeforeEof = 32,
					firstDataToUpstream = directFirstData,
                    connId = connId

				)
			} else {
				forwardTrafficAsync(
					upIn, cliOut,
					onDone = onBothDone,
					onEof  = { try { client.shutdownOutput() } catch (_: Exception) {} },
					srcSocket = upstream, dstSocket = client
				)
				forwardTrafficAsync(
					cliIn, upOut,
					onDone = onBothDone,
					onEof  = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
					minBytesBeforeEofCallback = 1,
					srcSocket = client, dstSocket = upstream
				)
			}
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Error in handleSocks4", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }


    // ====== Prime metrics (shared by LM & DIRECT) ======
    private val primeAttempts = AtomicLong(0)
    private val primeHits     = AtomicLong(0)
    private val primeBytesSum = AtomicLong(0)
    private fun recordPrime(bytes: Int) {
        primeAttempts.incrementAndGet()
        if (bytes > 0) {
            primeHits.incrementAndGet()
            primeBytesSum.addAndGet(bytes.toLong())
        }
    }


    // ====== SOCKS5 (CONNECT + UDP ASSOCIATE) ======
    private fun handleSocks5UdpAssociate(client: Socket, output: OutputStream) {
        try {
            val udpSocket = DatagramSocket(0)
            val udpPort = udpSocket.localPort
            val response = byteArrayOf(
                0x05, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                (udpPort shr 8).toByte(), (udpPort and 0xFF).toByte()
            )
            output.write(response); output.flush()

            threadPoolExecutor.execute {
                val buffer = ByteArray(65507)
                while (true) {
                    try {
                        val packet = DatagramPacket(buffer, buffer.size)
                        udpSocket.receive(packet)

                        val data = packet.data
                        if (data[2].toInt() != 0) continue // no frag support

                        val (_, _, payloadOffset) = parseUdpHeader(data)
                        val payload = data.copyOfRange(payloadOffset, packet.length)

                        // echo back for demo; real impl should send out and await resp
                        val respData = wrapSocks5Udp(DatagramPacket(payload, payload.size, packet.socketAddress))
                        val clientResp = DatagramPacket(respData, respData.size, packet.socketAddress)
                        udpSocket.send(clientResp)
                    } catch (_: Exception) {}
                }
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "UDP associate failed", e)
            try { client.close() } catch (_: Exception) {}
        }
    }

    private fun tuneSocket(ch: java.nio.channels.SocketChannel) {
        try {
            ch.socket().tcpNoDelay = true
        } catch (_: Exception) {}
        try {
            ch.socket().keepAlive = true
        } catch (_: Exception) {}
        try {
            // 禁用 SO_LINGER，防止 close() 主动发 RST
            ch.socket().setSoLinger(false, 0)
        } catch (_: Exception) {}
    }

    // 统一零等待 prime（LM/DIRECT/所有协议共用）：只读“已到达”的字节；不阻塞；带统计
    private fun capturePrimeNonBlocking(cliIn: BufferedInputStream, maxBytes: Int = 16 * 1024): ByteArray? {
        var n = 0
        return try {
            val avail = try { cliIn.available() } catch (_: Exception) { 0 }
            if (avail > 0) {
                val toRead = minOf(avail, maxBytes)
                val buf = ByteArray(toRead)
                n = cliIn.read(buf)
                if (n > 0) buf.copyOf(n) else null
            } else null
        } catch (_: Exception) {
            null
        } finally {
            // 复用你已存在的首包统计（若未引入，可按你之前的实现添加 recordPrime）
            try { recordPrime(n) } catch (_: Exception) {}
        }
    }

    private fun parseUdpHeader(data: ByteArray): Triple<String, Int, Int> {
        var offset = 3 // RSV(2)+FRAG
        val atyp = data[offset++].toInt()
        val destHost = when (atyp) {
            0x01 -> { val ip = data.copyOfRange(offset, offset + 4).joinToString(".") { (it.toInt() and 0xFF).toString() }; offset += 4; ip }
            0x03 -> { val len = data[offset++].toInt(); val domain = String(data.copyOfRange(offset, offset + len)); offset += len; domain }
            else -> "0.0.0.0"
        }
        val port = (data[offset++].toInt() shl 8) or (data[offset++].toInt() and 0xFF)
        return Triple(destHost, port, offset)
    }

    private fun wrapSocks5Udp(packet: DatagramPacket): ByteArray {
        val addr = packet.address.address
        val port = packet.port
        val header = ByteArray(3 + 1 + addr.size + 2)
        header[0] = 0x00; header[1] = 0x00; header[2] = 0x00
        header[3] = if (addr.size == 16) 0x04 else 0x01
        System.arraycopy(addr, 0, header, 4, addr.size)
        header[4 + addr.size] = (port shr 8).toByte()
        header[5 + addr.size] = (port and 0xFF).toByte()
        return header + packet.data.copyOfRange(0, packet.length)
    }

    private fun handleSocks5(client: Socket, input: InputStream, output: OutputStream, connId: Long, clientChOpt: SocketChannel? = null) {
        try {
            // Greeting
            input.read() // VER
            val nMethods = input.read()
            val methods = ByteArray(nMethods); input.read(methods)
            output.write(byteArrayOf(0x05, 0x00)) // no-auth
            output.flush()

            // Request
            input.read() // VER
            val cmd = input.read()
            input.read() // RSV
            val atyp = input.read()

            val destHost = when (atyp) {
                0x01 -> { val ip = ByteArray(4); input.read(ip); ip.joinToString(".") { (it.toInt() and 0xFF).toString() } }
                0x03 -> { val len = input.read(); val domain = ByteArray(len); input.read(domain); String(domain) }
                else -> { try { client.close() } catch (_: Exception) {}; onConnClose(connId); return }
            }
            val port = (input.read() shl 8) or input.read()

            val okResp = byteArrayOf(0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0)
            when (cmd) {
                0x01 -> { // CONNECT
                    output.write(okResp); output.flush()
                    // 统一：分支前“微等待 prime”（5–10ms；复用握手流）
                    val cliIn = if (input is BufferedInputStream) input else BufferedInputStream(input, 128 * 1024)
                    val firstData = capturePrimeAdaptive(cliIn, client, stepMs = 10, maxRounds = 5, maxBytes = 16 * 1024)


                    val isLayerMinus = (layerMinus != null)
                    Log.i(LOG_TAG, "SOCKS v5 proxy connect $destHost:$port via LayerMinus=$isLayerMinus")




                    val upstream: Socket? = if (isLayerMinus) {
                        layerMinus?.connectToLayerMinus(destHost, port.toString(), firstData)
                    } else {
                        try {
                            val ch = SocketChannel.open(InetSocketAddress(destHost, port))
                            tuneSocket(ch)
                            ch.socket()
                        } catch (e: Exception) {
                            Log.e(LOG_TAG, "Failed to connect to $destHost:$port", e); null
                        }
                    }


                    if (upstream == null) {
                        try { client.close() } catch (_: Exception) {}
                        onConnClose(connId); return
                    }

                    setSocketPerfOptions(client, upstream)  


					val clientChHere = clientChOpt
					val upstreamCh = upstream.channel as? SocketChannel
					val useSelector = (clientChHere != null && upstreamCh != null)


                    val upIn  = BufferedInputStream(upstream.getInputStream(),   128 * 1024)
                    val upOut = BufferedOutputStream(upstream.getOutputStream(), 128 * 1024)
                    val cliOut = BufferedOutputStream(output, 128 * 1024)


                    // DIRECT：若抓到了首包，先踢给上游
					val directFirstData = if (layerMinus == null) firstData else null
					if (!useSelector && directFirstData != null && directFirstData.isNotEmpty()) {
						try { upOut.write(directFirstData); upOut.flush() } catch (_: Exception) {}
					}

                    val remaining = java.util.concurrent.atomic.AtomicInteger(2)
                    val onBothDone = {
                        if (remaining.decrementAndGet() == 0) {
                            try { cliOut.flush() } catch (_: Exception) {}
                            try { upOut.flush() }  catch (_: Exception) {}
                            try { upstream.close() } catch (_: Exception) {}
                            try { client.close() }   catch (_: Exception) {}
                            onConnClose(connId)
                        }
                    }

					if (useSelector) {
						bridgeWithSelector(
							clientChHere!!, upstreamCh!!,
							onDone = {
								try { upstream.close() } catch (_: Exception) {}
								try { client.close() } catch (_: Exception) {}
								onConnClose(connId)
							},
							onClientEof = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
							onUpstreamEof = { try { client.shutdownOutput() } catch (_: Exception) {} },
							minClientBytesBeforeEof = 32,
							firstDataToUpstream = directFirstData,
                            connId = connId
						)
					} else {
						forwardTrafficAsync(
							upIn, cliOut,
							onDone = onBothDone,
							onEof  = { try { client.shutdownOutput() } catch (_: Exception) {} },
							srcSocket = upstream, dstSocket = client
						)
						forwardTrafficAsync(
							cliIn, upOut,
							onDone = onBothDone,
							onEof  = { try { upstream.shutdownOutput() } catch (_: Exception) {} },
							minBytesBeforeEofCallback = 1,
							srcSocket = client, dstSocket = upstream
						)
					}



                }
                0x03 -> { // UDP ASSOCIATE
                    handleSocks5UdpAssociate(client, output)
                    // Close will be logged when client disconnects; not handled here
                }
                else -> {
                    output.write(byteArrayOf(0x05, 0x07)) // Command not supported
                    output.flush()
                    try { client.close() } catch (_: Exception) {}
                    onConnClose(connId)
                }
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Error in handleSocks5", e)
            try { client.close() } catch (_: Exception) {}
            onConnClose(connId)
        }
    }

    // ====== Notification ======
    private fun createNotification(): Notification {
        return Notification.Builder(this, "SocketChannel")
            .setContentTitle("Socket Server Running")
            .setContentText("Listening on port 8888")
            .setSmallIcon(R.drawable.stat_notify_sync)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                "SocketChannel",
                "Socket Background Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(serviceChannel)
        }
    }
}
