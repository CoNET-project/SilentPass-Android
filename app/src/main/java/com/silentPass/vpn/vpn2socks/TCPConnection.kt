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

    private var clientSeq0: Long? = null            // Client initial SYN seq (as unsigned)
    private var clientNextSeq: Long = 0L            // Next expected seq from client (as unsigned)
    private var serverSeq: Long = Random.nextInt(0, Int.MAX_VALUE).toLong() // Our seq (as unsigned)
    private var established: Boolean = false

    fun isClosed(): Boolean = isClosed

    private val LOG_TAG = "TCPConnection"
    private val pendingLock = Mutex()
    private val pending = ArrayDeque<ByteArray>()   // Pending upstream writes (Client->Server)

    // Buffer for early upstream data before handshake completes
    private val downPrimeLock = Mutex()
    private var downPrime: ByteArray? = null

    // Out-of-order buffer for reassembly
    private data class Segment(val seq: Long, val data: ByteArray)
    private val outOfOrderSegments = mutableListOf<Segment>()
    private val maxOutOfOrderSize = 20

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

        // SYN (client -> us): Record initial seq, async establish upstream, send SYN-ACK
        if (tcp.isSYN && !tcp.isACK) {
            val domain = dns.lookupDomain(ip.dst)
            clientSeq0 = tcp.seq.toLong() and 0xFFFFFFFFL  // Convert to unsigned long
            clientNextSeq = (clientSeq0!! + 1L) and 0xFFFFFFFFL

            // Async establish upstream (don't block client handshake)
            scope.launch { establishUpstream(ip, tcp, domain) }

            // Send SYN-ACK
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
            serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL  // SYN consumes 1 seq number
            return
        }

        // Pure ACK for our SYN-ACK (completes 3-way handshake)
        if (!established && tcp.isACK && !tcp.isSYN && tcp.payload.isEmpty()) {
            val ackNum = tcp.ack.toLong() and 0xFFFFFFFFL
            if (ackNum == serverSeq) {
                stateLock.withLock {
                    established = true
                }
                Log.d(LOG_TAG, "3-way handshake established for $key")

                // Start downstream if upstream is ready
                tryStartDownstream(ip, tcp)
            }
            return
        }

        // FIN: Enter teardown
        if (tcp.isFIN) {
            Log.d(LOG_TAG, "FIN received for $key")
            clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL  // FIN consumes 1 seq

            // ACK the FIN
            sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())

            // Send our FIN
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
            closeConnection()
            return
        }

        // Established: Handle upstream data (including with FIN)
        if (established) {
            // Process any payload data first
            if (tcp.payload.isNotEmpty()) {
                handleEstablishedData(ip, tcp)
            }

            // Then check for FIN
            if (tcp.isFIN) {
                Log.d(LOG_TAG, "FIN received for $key (after processing ${tcp.payload.size} bytes)")

                // Flush any remaining data
                scope.launch {
                    tryFlushUpstream()
                    // Wait for any response
                    delay(100)

                    clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL  // FIN consumes 1 seq

                    // ACK the FIN
                    sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())

                    // Send our FIN
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

                    // Don't close immediately - let downstream read any response
                    delay(500)
                    closeConnection()
                }
                return
            }
            return
        }

        // Not established: check for FIN during handshake
        if (tcp.isFIN) {
            Log.d(LOG_TAG, "FIN received during handshake for $key")
            // Handle early FIN...
            clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
            sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
            closeConnection()
            return
        }
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

            // Try to flush to upstream
            upstreamWriter?.let {
                tryFlushUpstream()
            }

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
            // Future segment (out-of-order)
            Log.d(LOG_TAG, "Out-of-order segment seq=$segSeq expect=$expect, buffering")

            // Buffer it if we have space
            if (outOfOrderSegments.size < maxOutOfOrderSize) {
                // Check if we already have this segment
                val exists = outOfOrderSegments.any { it.seq == segSeq }
                if (!exists) {
                    outOfOrderSegments.add(Segment(segSeq, tcp.payload.copyOf()))
                    outOfOrderSegments.sortBy { it.seq }
                    Log.d(LOG_TAG, "Buffered out-of-order segment, buffer size: ${outOfOrderSegments.size}")
                }
            }

            // Send duplicate ACK to trigger fast retransmit
            sendPureAck(ip, tcp, ackOverride = clientNextSeq.toInt())
        }
    }

    // Deliver any buffered segments that are now in-order
    private suspend fun deliverBufferedSegments() {
        while (outOfOrderSegments.isNotEmpty()) {
            val first = outOfOrderSegments.first()

            if (first.seq == clientNextSeq) {
                // This segment is now in order
                outOfOrderSegments.removeAt(0)
                val segEnd = (first.seq + first.data.size.toLong()) and 0xFFFFFFFFL
                clientNextSeq = segEnd

                Log.d(LOG_TAG, "Delivering buffered segment seq=${first.seq}, ${first.data.size} bytes")

                // Queue for upstream
                pendingLock.withLock {
                    pending.addLast(first.data)
                }
                upstreamWriter?.let { tryFlushUpstream() }

            } else if (isSeqBefore(first.seq, clientNextSeq)) {
                // This is old data, remove it
                outOfOrderSegments.removeAt(0)
            } else {
                // Still have a gap
                break
            }
        }
    }

    // TCP sequence number comparison (handles wraparound)
    private fun isSeqBefore(seq1: Long, seq2: Long): Boolean {
        val diff = (seq1 - seq2) and 0xFFFFFFFFL
        return diff > 0x80000000L  // More than half the sequence space
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
                s.soTimeout = 0  // Back to blocking
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
                established && upstreamConnected
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

                // Start downstream loop
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

        // Make sure we've flushed all pending data first
        delay(50) // Small delay to ensure initial client data is sent

        try {
            Log.d(LOG_TAG, "Downstream loop started for $key")
            while (!isClosed) {
                val n = try {
                    inp.read(buf)
                } catch (e: java.net.SocketTimeoutException) {
                    // Timeout is OK, just retry
                    continue
                }

                if (n <= 0) {
                    Log.i(LOG_TAG, "Downstream EOF for $key")
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