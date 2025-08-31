package com.silentPass.vpn.vpn2socks

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.Socket
import kotlin.random.Random

class TCPConnection(
    private val key: String,
    private val mtu: Int,
    private val packetWriter: (List<ByteArray>, List<Int>) -> Unit,
    private val dns: DNSInterceptor,
    private val socksEndpoint: SocksEndpoint,
    private val bypassDirect: Boolean
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // === Upstream socket / IO ===
    private var upstream: Socket? = null
    private var upstreamWriter: java.io.OutputStream? = null
    private var upstreamReader: java.io.InputStream? = null

    // === Synchronization & State ===
    private val writeLock = Mutex()
    private val stateLock = Mutex()
    private var isClosed = false
    private var upstreamConnected = false

    private var clientSeq0: Long? = null
    private var clientNextSeq: Long = 0L
    private var serverSeq: Long = Random.nextInt(0, Int.MAX_VALUE).toLong()
    private var established: Boolean = false

    fun isClosed(): Boolean = isClosed

    private val LOG_TAG = "TCPConnection"
    private val pendingLock = Mutex()
    private val pending = ArrayDeque<ByteArray>()

    // Buffer for early upstream data before handshake completes
    private val downPrimeLock = Mutex()
    private var downPrime: ByteArray? = null

    // Out-of-order buffer for reassembly - ADD MUTEX FOR THREAD SAFETY
    private data class Segment(val seq: Long, val data: ByteArray)
    private val outOfOrderLock = Mutex()  // ADD THIS
    private val outOfOrderSegments = mutableListOf<Segment>()
    private val maxOutOfOrderSize = 20

    private var clientHalfClosed = false
    private var pendingShutdown = false
    private var downstreamStarted = false

    // =============== Main Entry ===============
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

        // RST: Immediate close
        if (tcp.isRST) {
            Log.d(LOG_TAG, "RST received for $key")
            closeConnection()
            return
        }

        // SYN (client -> us)
        if (tcp.isSYN && !tcp.isACK) {
            val domain = dns.lookupDomain(ip.dst)
            clientSeq0 = tcp.seq.toLong() and 0xFFFFFFFFL
            clientNextSeq = (clientSeq0!! + 1L) and 0xFFFFFFFFL

            scope.launch { establishUpstream(ip, tcp, domain) }

            val synAck = IpBuilders.tcpPayloadFromServer(
                src = ip.dst, dst = ip.src,
                srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                payload = ByteArray(0),
                seq = serverSeq.toInt(),
                ack = clientNextSeq.toInt(),
                flags = 0x12, // SYN | ACK
                window = 65535
            )
            packetWriter(listOf(synAck), listOf(ConnectionManager.PROTO_IPV4))
            serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL
            return
        }

        // Handle ACK that completes handshake
        if (!established && tcp.isACK && !tcp.isSYN) {
            val ackNum = tcp.ack.toLong() and 0xFFFFFFFFL
            if (ackNum == serverSeq) {
                stateLock.withLock { established = true }
                Log.d(LOG_TAG, "3-way handshake established for $key")
                tryStartDownstream(ip, tcp)

                if (tcp.payload.isNotEmpty()) {
                    Log.d(LOG_TAG, "Processing ${tcp.payload.size} bytes of early data with handshake ACK")
                    handleEstablishedData(ip, tcp)
                }

                // Check if FIN flag is also set (combined ACK+FIN)
                if (tcp.isFIN) {
                    handleFIN(ip, tcp)
                }
                return
            }
        }

        // Handle established connection
        if (established) {
            if (tcp.payload.isNotEmpty()) {
                handleEstablishedData(ip, tcp)
            }

            if (tcp.isFIN) {
                handleFIN(ip, tcp)
            }
            return
        }

        // Handle FIN before establishment (connection abort)
        if (tcp.isFIN) {
            Log.d(LOG_TAG, "FIN received before establishment for $key")
            clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
            sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
            closeConnection()
            return
        }

        // Unexpected data before handshake
        if (tcp.payload.isNotEmpty()) {
            Log.w(LOG_TAG, "Data received before handshake complete: ${tcp.payload.size} bytes")
        }
    }

    // Extract FIN handling to a separate method for clarity
    private suspend fun handleFIN(ip: IPv4Packet, tcp: TCPSegment) {
        Log.d(LOG_TAG, "FIN received for $key (client half-close)")
        clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
        sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())

        stateLock.withLock {
            clientHalfClosed = true
            pendingShutdown = true
        }

        tryFlushUpstream()
    }

    // =============== Handle Established Data ===============
    private suspend fun handleEstablishedData(ip: IPv4Packet, tcp: TCPSegment) {
        val segSeq = tcp.seq.toLong() and 0xFFFFFFFFL
        val dataLen = tcp.payload.size.toLong()
        val segEnd = (segSeq + dataLen) and 0xFFFFFFFFL
        val expect = clientNextSeq

        // Check if this is the expected segment
        if (segSeq == expect) {
            // Perfect in-order segment
            Log.d(LOG_TAG, "Client->Server (in-order): $dataLen bytes for $key")
            clientNextSeq = segEnd

            // Queue for upstream
            pendingLock.withLock {
                pending.addLast(tcp.payload.copyOf())
            }

            tryFlushUpstream()

            // Check if we can now deliver buffered out-of-order segments
            deliverBufferedSegments()

            // Send ACK for all received data
            sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())

        } else if (isSeqBefore(segSeq, expect)) {
            // Old segment (possible retransmission)
            if (isSeqBefore(segEnd, expect)) {
                // Completely old data
                Log.d(LOG_TAG, "Duplicate segment seq=$segSeq expect=$expect, ACK")
                sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
            } else {
                // Partial overlap - some new data
                val overlap = (expect - segSeq).toInt()
                val newData = tcp.payload.copyOfRange(overlap, tcp.payload.size)
                Log.d(LOG_TAG, "Partial retrans: ${newData.size} new bytes")

                clientNextSeq = segEnd
                pendingLock.withLock {
                    pending.addLast(newData)
                }
                upstreamWriter?.let { tryFlushUpstream() }
                sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
            }

        } else {
            // Future segment (out-of-order) - FIX THE CONCURRENT MODIFICATION HERE
            Log.d(LOG_TAG, "Out-of-order segment seq=$segSeq expect=$expect, buffering")

            // Buffer it if we have space - WITH LOCK
            outOfOrderLock.withLock {
                if (outOfOrderSegments.size < maxOutOfOrderSize) {
                    val exists = outOfOrderSegments.any { it.seq == segSeq }
                    if (!exists) {
                        outOfOrderSegments.add(Segment(segSeq, tcp.payload.copyOf()))
                        outOfOrderSegments.sortBy { it.seq }  // Now safe within lock
                        Log.d(LOG_TAG, "Buffered out-of-order segment, buffer size: ${outOfOrderSegments.size}")
                    }
                }
            }

            // Send duplicate ACK to trigger fast retransmit
            sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
        }
    }

    // Deliver any buffered segments that are now in-order - FIX WITH LOCKS
    private suspend fun deliverBufferedSegments() {
        while (true) {
            // Get and remove first segment atomically if it exists
            val first = outOfOrderLock.withLock {
                if (outOfOrderSegments.isNotEmpty()) {
                    val seg = outOfOrderSegments.first()
                    if (seg.seq == clientNextSeq) {
                        // Remove and return it
                        outOfOrderSegments.removeAt(0)
                        seg
                    } else if (isSeqBefore(seg.seq, clientNextSeq)) {
                        // Old data, remove it
                        outOfOrderSegments.removeAt(0)
                        null // Signal to continue loop but don't process
                    } else {
                        // Gap exists, stop processing
                        return@withLock null
                    }
                } else {
                    null // List is empty
                }
            }

            // Process the segment if we got one
            if (first != null) {
                val segEnd = (first.seq + first.data.size.toLong()) and 0xFFFFFFFFL
                clientNextSeq = segEnd

                Log.d(LOG_TAG, "Delivering buffered segment seq=${first.seq}, ${first.data.size} bytes")

                // Queue for upstream
                pendingLock.withLock {
                    pending.addLast(first.data)
                }
                upstreamWriter?.let { tryFlushUpstream() }
            } else {
                // Either list was empty or we hit a gap
                break
            }
        }
    }

    // TCP sequence number comparison (handles wraparound)
    private fun isSeqBefore(seq1: Long, seq2: Long): Boolean {
        val diff = (seq1 - seq2) and 0xFFFFFFFFL
        return diff > 0x80000000L
    }

    // =============== Upstream Establishment ===============
    private suspend fun establishUpstream(ip: IPv4Packet, syn: TCPSegment, domain: String?) = withContext(Dispatchers.IO) {
        try {
            val port = syn.dstPort
            val hostForDial = if (domain != null) {
                Log.d(LOG_TAG, "Using domain: $domain for SOCKS dial")
                domain
            } else {
                Log.d(LOG_TAG, "No domain found, using IP: ${ip.dst}")
                ip.dst.toString()
            }

            val s = if (bypassDirect) {
                Log.d(LOG_TAG, "Direct dial $hostForDial:$port (bypass)")
                val socket = Socket()
                socket.tcpNoDelay = true
                val protectResult = Vpn2SocksService.protectSocket(socket)
                Log.d(LOG_TAG, "Socket protection result: $protectResult")
                socket.connect(java.net.InetSocketAddress(hostForDial, port), 15000)
                socket
            } else {
                Log.d(LOG_TAG, "Dial SOCKS ${socksEndpoint.host}:${socksEndpoint.port} for $hostForDial:$port")
                val socket = SocksClient(socksEndpoint).dial(hostForDial, port)
                socket.tcpNoDelay = true
                Log.d(LOG_TAG, "SOCKS dial completed successfully for $hostForDial:$port")
                socket
            }

            upstream = s
            upstreamWriter = s.getOutputStream()
            upstreamReader = s.getInputStream()

            stateLock.withLock {
                upstreamConnected = true
            }

            // Flush any pending upstream data
            tryFlushUpstream()

            // Check for early upstream data
            s.soTimeout = 5
            try {
                val avail = upstreamReader?.available() ?: 0
                if (avail > 0) {
                    val buf = ByteArray(kotlin.math.min(2048, avail))
                    val n = upstreamReader!!.read(buf)
                    if (n > 0) {
                        downPrimeLock.withLock {
                            downPrime = buf.copyOf(n)
                        }
                        Log.d(LOG_TAG, "Prime-downstream buffered: $n bytes for $key")
                    }
                }
            } catch (e: Exception) {
                Log.w(LOG_TAG, "Prime read failed: ${e.message}")
            } finally {
                s.soTimeout = 0
            }

            Log.d(LOG_TAG, "SOCKS connected and primed, waiting for client ACK to start downstream pump")

            // Try to start downstream if handshake is done
            tryStartDownstream(ip, syn)

        } catch (t: Throwable) {
            Log.e(LOG_TAG, "Upstream connect failed for $key: ${t.message}", t)
            closeConnection()
        }
    }

    // Start downstream loop if both handshake and upstream are ready
    private fun tryStartDownstream(ip: IPv4Packet, tcp: TCPSegment) {
        scope.launch {
            val canStart = stateLock.withLock {
                if (downstreamStarted) {
                    return@withLock false
                }
                if (established && upstreamConnected) {
                    downstreamStarted = true
                    true
                } else {
                    false
                }
            }

            if (canStart) {
                // Send any primed data
                val prime = downPrimeLock.withLock {
                    val p = downPrime
                    downPrime = null
                    p
                }

                if (prime != null && prime.isNotEmpty()) {
                    sendDataToClient(ip, tcp, prime)
                    Log.d(LOG_TAG, "Prime-downstream sent: ${prime.size} bytes")
                }

                // Start downstream loop - only once!
                downstreamLoop(ip, tcp)
            }
        }
    }

    // =============== Send Data to Client ===============
    private fun sendDataToClient(ip: IPv4Packet, tcp: TCPSegment, data: ByteArray) {
        val mss = (mtu - 40).coerceAtLeast(536)
        var off = 0

        while (off < data.size && !isClosed) {
            val take = kotlin.math.min(mss, data.size - off)
            val payload = data.copyOfRange(off, off + take)

            val pkt = IpBuilders.tcpPayloadFromServer(
                src = ip.dst, dst = ip.src,
                srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                payload = payload,
                seq = serverSeq.toInt(),
                ack = clientNextSeq.toInt(),
                flags = 0x18, // PSH | ACK
                window = 65535
            )
            packetWriter(listOf(pkt), listOf(ConnectionManager.PROTO_IPV4))
            serverSeq = (serverSeq + take.toLong()) and 0xFFFFFFFFL
            off += take
        }
    }

    // =============== Downstream Pump: Server->Client ===============
    private suspend fun downstreamLoop(ip: IPv4Packet, tcp: TCPSegment) = withContext(Dispatchers.IO) {
        val inp = upstreamReader ?: return@withContext
        val buf = ByteArray(32 * 1024)

        delay(50)

        try {
            Log.d(LOG_TAG, "Downstream loop started for $key")
            while (!isClosed) {
                val n = try {
                    inp.read(buf)
                } catch (e: java.net.SocketTimeoutException) {
                    continue
                }

                if (n <= 0) {
                    Log.i(LOG_TAG, "Downstream EOF for $key (server done sending)")
                    try {
                        val finAck = IpBuilders.tcpPayloadFromServer(
                            src = ip.dst, dst = ip.src,
                            srcPort = tcp.dstPort, dstPort = tcp.srcPort,
                            payload = ByteArray(0),
                            seq = serverSeq.toInt(),
                            ack = clientNextSeq.toInt(),
                            flags = 0x11, // FIN | ACK
                            window = 65535
                        )
                        packetWriter(listOf(finAck), listOf(ConnectionManager.PROTO_IPV4))
                        Log.d(LOG_TAG, "Sent FIN|ACK to client for $key after downstream EOF")
                    } catch (_: Throwable) {}
                    break
                }

                Log.d(LOG_TAG, "Server->Client: $n bytes for $key")
                sendDataToClient(ip, tcp, buf.copyOf(n))
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Downstream loop error: ${e.message}, ${e.javaClass.simpleName}")
        } finally {
            closeConnection()
        }
    }

    // =============== Upstream Write (Client->Server) ===============
    private suspend fun tryFlushUpstream() = withContext(Dispatchers.IO) {
        val out = upstreamWriter ?: return@withContext

        while (true) {
            val chunk = pendingLock.withLock {
                if (pending.isEmpty()) null else pending.removeFirst()
            }
            if (chunk == null) break

            try {
                writeLock.withLock {
                    if (!isClosed) {
                        Log.d(LOG_TAG, "Writing ${chunk.size} bytes to upstream")
                        out.write(chunk)
                        out.flush()
                        Log.d(LOG_TAG, "Successfully wrote to upstream")
                    }
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Upstream write failed: ${e.message}")
                closeConnection()
                break
            }
        }

        // After all data is flushed, check if we need to shutdown
        val shouldShutdown = stateLock.withLock {
            pendingShutdown && pending.isEmpty()
        }

        if (shouldShutdown) {
            try {
                upstream?.shutdownOutput()
                Log.d(LOG_TAG, "Upstream output shutdown after flushing all data")
            } catch (e: Throwable) {
                Log.w(LOG_TAG, "Shutdown upstream output failed: ${e.message}")
            }
        }
    }

    // Send pure ACK
    private fun sendPureAck(ip: IPv4Packet, tcp: TCPSegment, ackOverride: Int? = null) {
        val ackPacket = IpBuilders.tcpPayloadFromServer(
            src = ip.dst, dst = ip.src,
            srcPort = tcp.dstPort, dstPort = tcp.srcPort,
            payload = ByteArray(0),
            seq = serverSeq.toInt(),
            ack = ackOverride ?: clientNextSeq.toInt(),
            flags = 0x10, // ACK
            window = 65535
        )
        packetWriter(listOf(ackPacket), listOf(ConnectionManager.PROTO_IPV4))
    }

    private fun closeConnection() {
        if (isClosed) return
        isClosed = true

        scope.launch {
            try { upstreamReader?.close() } catch (_: Throwable) {}
            try { upstreamWriter?.close() } catch (_: Throwable) {}
            try { upstream?.close() } catch (_: Throwable) {}
            upstreamReader = null
            upstreamWriter = null
            upstream = null
        }
        scope.cancel()
    }
}