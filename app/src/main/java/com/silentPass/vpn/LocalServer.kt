package com.silentPass.vpn
import android.R
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.text.TextUtils.isEmpty
import android.util.Log
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import android.util.Base64

import com.google.gson.Gson
import java.io.ByteArrayOutputStream
import kotlin.ByteArray
import java.net.DatagramSocket
import java.net.DatagramPacket
import java.net.InetSocketAddress
import java.net.SocketException

class SocketServerService : Service() {

    private var serverThread: Thread? = null
    private var isRunning = true
    private var layerMinus: LayerMinus? = null
    private var serverSocket: ServerSocket? = null
    private val LOG_TAG = "SocketServerService"
    private fun forwardTraffic(input: InputStream, output: OutputStream) {
        Thread {
            try {
                val buffer = ByteArray(4096)
                var bytes: Int
                while (true) {
                    bytes = input.read(buffer)
                    if (bytes == -1) {
                        // 正常的 EOF，不是错误
                        Log.d(LOG_TAG, "forwardTraffic: EOF reached, closing gracefully")
                        break
                    }
                    output.write(buffer, 0, bytes)
                    output.flush()
                }
            } catch (e: java.net.SocketException) {
                // Socket 关闭是正常的，不需要记录为错误
                Log.d(LOG_TAG, "forwardTraffic: Socket closed (normal)")
            } catch (e: Exception) {
                Log.e(LOG_TAG, "forwardTraffic: Unexpected error", e)
            } finally {
                try {
                    input.close()
                    output.close()
                } catch (_: Exception) {}
            }
        }.start()
    }
    //      curl local proxy test command
    //      curl -v -x socks5://127.0.0.1:8888 --resolve "www.google.com:53:8.8.8.8" www.google.com
    //      curl -v -x socks5://127.0.0.1:8888 https://www.google.com
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val base64 = intent?.getStringExtra("VPN_DATA_B64")
        if (base64 != null) {
            try {
                val decodedBytes = Base64.decode(base64, Base64.DEFAULT)
                val jsonString = String(decodedBytes, Charsets.UTF_8)
                var startVPNData = Gson().fromJson(jsonString, StartVPNData::class.java)
                LayerMinus.init(startVPNData)
                this.layerMinus = LayerMinus

                // Use vpnData to start your server...
            } catch (e: Exception) {
                Log.e("SocketServerService", "Failed to parse VPN data", e)
            }
        }

        if (serverThread == null || !serverThread!!.isAlive) {
            startSocketServer()
        }
        return START_STICKY
    }

    private fun startSocketServer() {
        serverThread = Thread {
            try {
                serverSocket = ServerSocket(8888, 50)
                Log.d("SocketServer", "Server started on port 8888")

                while (isRunning) {
                    val client = serverSocket?.accept() ?: break
                    handleClient(client)
                }
                serverSocket?.close()
            } catch (e: Exception) {
                Log.e("SocketServer", "Server error", e)
            }
        }
        serverThread?.start()
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(1, createNotification()) // REQUIRED WITHIN 5s
        Log.d(LOG_TAG, "Service created")
    }

    private fun handleHttpProxy(client: Socket, requestLine: String?, reader: BufferedReader) {
        Thread {
            if (requestLine == null) {
                Log.e(LOG_TAG, "Null request line")
                client.close()
                return@Thread
            }

            try {
                Log.d(LOG_TAG, "Request Line: $requestLine")

                val headers = mutableListOf<String>()
                var line: String?
                while (reader.readLine().also { line = it } != null && line!!.isNotEmpty()) {
                    headers.add(line!!)
                }

                val parts = requestLine.split(" ")

                if (parts.size < 3) {
                    Log.e(LOG_TAG, "Invalid request line")
                    client.close()
                    return@Thread
                }

                val method = parts[0]
                val fullUrl = parts[1]
                val httpVersion = parts[2]

                val url = URL(fullUrl)

                val host = url.host
                val port = if (url.port != -1) url.port else 80
                val path = url.file.ifEmpty { "/" }

                Log.d(LOG_TAG, "Target: $host:$port$path")

                var body: CharArray? = null
                val contentLength = headers
                    .find { it.startsWith("Content-Length", ignoreCase = true) }
                    ?.split(":")?.getOrNull(1)?.trim()?.toIntOrNull() ?: 0

                if (contentLength > 0) {
                    body = CharArray(contentLength)
                    reader.read(body)
                }

                var requestBody = "$method $path $httpVersion\r\n"

                for (header in headers) {
                    if (!header.startsWith("Proxy-", ignoreCase = true)) {
                        requestBody += "$header\r\n"
                    }
                }

                requestBody += "\r\n"

                if (body != null) {
                    requestBody += String(body!!)
                }

                val serverSocket: Socket?
                if (layerMinus != null) {

                    serverSocket = layerMinus?.connectToLayerMinus(host, port.toString(), requestBody.toByteArray(Charsets.UTF_8))
                    if (serverSocket != null) {
                        val serverInput = BufferedInputStream(serverSocket.getInputStream())
                        val clientOutput = client.getOutputStream()
                        forwardTraffic(serverInput, clientOutput)
                    } else {
                        client.close()
                        return@Thread
                    }
                } else {
                    serverSocket = Socket(host, port)
                    if (serverSocket == null) {
                        client.close()
                        return@Thread
                    }

                    val serverOutput = BufferedWriter(OutputStreamWriter(serverSocket.getOutputStream()))
                    val serverInput = BufferedInputStream(serverSocket.getInputStream())
                    val clientOutput = client.getOutputStream()

                    // Rewrite request line (strip full URL)
                    serverOutput.write(requestBody)
                    serverOutput.flush()


                    // Pipe the response back to client
                    forwardTraffic(serverInput, clientOutput)
                }

            } catch (e: Exception) {
                Log.e(LOG_TAG, "Error: ${e.message}", e)
                try {
                    client.close()
                } catch (_: Exception) {}
            }
        }.start()
    }

    private fun readFirstChunkOrNull(ins: InputStream): ByteArray? {
        val buf = ByteArray(4096)
        val n = try { ins.read(buf) } catch (e: Exception) { return null }
        return when {
            n > 0  -> buf.copyOf(n)     // 首包
            n == 0 -> ByteArray(0)      // 极少见，但允许空首包
            else   -> null              // -1，立刻返回 null（不传首包）
        }
    }

    private fun handleHttpsConnect(client: Socket, requestLine: String) {
        Thread {
            try {
                val parts = requestLine.split(" ")
                val target = parts[1]
                val host = target.substringBefore(":")
                val port = target.substringAfter(":").toIntOrNull() ?: 443


                val clientWriter = BufferedWriter(OutputStreamWriter(client.getOutputStream()))
                clientWriter.write("HTTP/1.1 200 Connection Established\r\n\r\n")
                clientWriter.flush()

                if (layerMinus != null) {
                    val inputStream: InputStream = client.getInputStream()
                    val firstData: ByteArray? = readFirstChunkOrNull(inputStream)
                    Log.d(LOG_TAG, "rawBytes length = ${firstData?.size ?: 0}")
                    val serverSocket = layerMinus?.connectToLayerMinus(host, port.toString(), firstData)





                    if (serverSocket == null) {
                        client.close()
                        return@Thread
                    }

                    val serverInput = BufferedInputStream(serverSocket.getInputStream())


                    val clientOutput = client.getOutputStream()
                    forwardTraffic(serverInput, clientOutput)
                    forwardTraffic(client.getInputStream(), serverSocket.getOutputStream())
                } else {
                    var targetSocket = Socket(host, port)


                if (targetSocket == null) {
                    client.close()
                    return@Thread
                }

                forwardTraffic(client.getInputStream(), targetSocket.getOutputStream())
                forwardTraffic(targetSocket.getInputStream(), client.getOutputStream())
                Log.d(
                    LOG_TAG,
                    "Forwarding ${host}:${port} via Local CONNECTING"
                )
                    }

            } catch (e: Exception) {
                Log.e(LOG_TAG, "HTTPS CONNECT failed", e)
                client.close()
                return@Thread
            }
        }.start()
    }

    private fun handleSocks4(client: Socket, input: InputStream, output: OutputStream) {
        Thread {
            val version = input.read()
            val command = input.read()
            val port = (input.read() shl 8) or input.read()
            val ip = ByteArray(4)
            input.read(ip)

            val userId = StringBuilder()
            var b: Int
            while (input.read().also { b = it } != 0 && b != -1) {
                userId.append(b.toChar())
            }

            val isSocks4a =
                ip[0].toInt() == 0 && ip[1].toInt() == 0 && ip[2].toInt() == 0 && ip[3].toInt() != 0
            val destHost = if (isSocks4a) {
                val sb = StringBuilder()
                while (input.read().also { b = it } != 0 && b != -1) {
                    sb.append(b.toChar())
                }
                sb.toString()
            } else {
                ip.joinToString(".") { (it.toInt() and 0xFF).toString() }
            }

            val response = byteArrayOf(0x00, 0x5a, 0, 0, 0, 0, 0, 0) // request granted
            if (layerMinus != null) {
                val inputStream: InputStream = client.getInputStream()
                val firstData: ByteArray? = readFirstChunkOrNull(inputStream)
                Log.d("handleHttpsConnect", "rawBytes length = ${firstData?.size ?: 0}")
                val serverSocket =
                    layerMinus?.connectToLayerMinus(destHost, port.toString(), firstData)





                if (serverSocket == null) {
                    client.close()
                    return@Thread
                }

                val serverInput = BufferedInputStream(serverSocket.getInputStream())
                val clientOutput = client.getOutputStream()
                forwardTraffic(serverInput, clientOutput)
                forwardTraffic(client.getInputStream(), serverSocket.getOutputStream())
            } else {
                try {
                    val target = Socket(destHost, port)

                    output.write(response)
                    output.flush()

                    forwardTraffic(input, target.getOutputStream())
                    forwardTraffic(target.getInputStream(), output)
                } catch (e: Exception) {
                    Log.e(LOG_TAG, "Connection error", e)
                    output.write(byteArrayOf(0x00, 0x5b)) // request rejected
                    output.flush()
                    client.close()
                    return@Thread
                }
            }
        }.start()

    }

    private fun parseUdpHeader(data: ByteArray): Triple<String, Int, Int> {
        var offset = 3 // skip RSV and FRAG
        val atyp = data[offset++].toInt()
        val destHost = when (atyp) {
            0x01 -> { // IPv4
                val ip = data.copyOfRange(offset, offset + 4).joinToString(".") { (it.toInt() and 0xFF).toString() }
                offset += 4
                ip
            }
            0x03 -> { // Domain
                val len = data[offset++].toInt()
                val domain = String(data.copyOfRange(offset, offset + len))
                offset += len
                domain
            }
//            0x04 -> { // IPv6 not support
//                val ip = InetAddress.getByAddress(data.copyOfRange(offset, offset + 16)).hostAddress
//                offset += 16
//                ip
//            }
            else -> "0.0.0.0"
        }
        val port = (data[offset++].toInt() shl 8) or (data[offset++].toInt() and 0xFF)
        return Triple(destHost, port, offset)
    }

    private fun wrapSocks5Udp(packet: DatagramPacket): ByteArray {
        val addr = packet.address.address
        val port = packet.port
        val header = ByteArray(3 + 1 + addr.size + 2)
        header[0] = 0x00 // RSV
        header[1] = 0x00
        header[2] = 0x00 // FRAG
        header[3] = when (addr.size) {
            4 -> 0x01.toByte() // IPv4
            16 -> 0x04.toByte() // IPv6
            else -> 0x01.toByte()
        }
        System.arraycopy(addr, 0, header, 4, addr.size)
        header[4 + addr.size] = (port shr 8).toByte()
        header[5 + addr.size] = (port and 0xFF).toByte()

        return header + packet.data.copyOfRange(0, packet.length)
    }

    private fun handleSocks5UdpAssociate(client: Socket, output: OutputStream) {
        try {
            val udpSocket = DatagramSocket(0)
            val udpPort = udpSocket.localPort

            // Respond to client with UDP bind info (0.0.0.0:udpPort)
            val response = byteArrayOf(
                0x05, 0x00, 0x00, 0x01, // VER, REP=OK, RSV, ATYP=IPv4
                0x00, 0x00, 0x00, 0x00, // BND.ADDR = 0.0.0.0
                (udpPort shr 8).toByte(), (udpPort and 0xFF).toByte()
            )
            output.write(response)
            output.flush()

            Thread {
                val buffer = ByteArray(65507)
                while (true) {
                    try {
                        val packet = DatagramPacket(buffer, buffer.size)
                        udpSocket.receive(packet)

                        val data = packet.data
                        val frag = data[2].toInt()
                        if (frag != 0) continue // we don't support fragmentation

                        val atyp = data[3].toInt()
                        val (targetHost, targetPort, payloadOffset) = parseUdpHeader(data)

                        val payload = data.copyOfRange(payloadOffset, packet.length)

                        val targetAddr = InetSocketAddress(targetHost, targetPort)
                        val forwardPacket = DatagramPacket(payload, payload.size, targetAddr)
                        udpSocket.send(forwardPacket)

                        // Optional: Read response from target and send back to client (with SOCKS5 header)
                        val responseBuf = ByteArray(65507)
                        val responsePacket = DatagramPacket(responseBuf, responseBuf.size)
                        udpSocket.receive(responsePacket)

                        val responseData = wrapSocks5Udp(responsePacket)
                        val clientResponse = DatagramPacket(
                            responseData, responseData.size, packet.socketAddress
                        )
                        udpSocket.send(clientResponse)
                    } catch (_: Exception) {}
                }
            }.start()
        } catch (e: Exception) {
            Log.e(LOG_TAG, "UDP associate failed", e)
            client.close()
        }
    }

    private fun handleSocks5(client: Socket, input: InputStream, output: OutputStream) {
        Thread {
            try {
                input.read() // version
                val nMethods = input.read()
                val methods = ByteArray(nMethods)
                input.read(methods)

                // Respond with no auth
                output.write(byteArrayOf(0x05, 0x00))
                output.flush()

                val version = input.read()
                val cmd = input.read()
                input.read() // RSV
                val atyp = input.read()

                val destHost = when (atyp) {
                    0x01 -> { // IPv4
                        val ip = ByteArray(4)
                        input.read(ip)
                        ip.joinToString(".") { (it.toInt() and 0xFF).toString() }
                    }

                    0x03 -> { // Domain name
                        val len = input.read()
                        val domain = ByteArray(len)
                        input.read(domain)
                        String(domain)
                    }
//
//                0x04 -> { // IPv6 not support
//                    val ip = ByteArray(16)
//                    input.read(ip)
//                    InetAddress.getByAddress(ip).hostAddress
//                }

                    else -> {
                        client.close()
                        return@Thread
                    }
                }

                val port = (input.read() shl 8) or input.read()

                val response = byteArrayOf(
                    0x05, 0x00, 0x00, 0x01, // VER, REP=success, RSV, ATYP=IPv4
                    0x00, 0x00, 0x00, 0x00, // BND.ADDR (dummy)
                    0x00, 0x00              // BND.PORT (dummy)
                )

                when (cmd) {
                    0x01 -> { // CONNECT
                        if (layerMinus != null) {
                            output.write(response)
                            output.flush()

                            Thread {
                                var remoteSocket: Socket? = null  // 改名为 remoteSocket 避免混淆
                                try {
                                    val buffer = ByteArray(4096)
                                    var firstPacketSent = false

                                    while (true) {
                                        val bytesRead = try {
                                            input.read(buffer)
                                        } catch (e: java.net.SocketException) {
                                            if (e.message?.contains("closed") == true) {
                                                Log.d(LOG_TAG, "Client socket closed (normal)")
                                                break
                                            } else {
                                                throw e
                                            }
                                        }

                                        if (bytesRead == -1) break

                                        if (!firstPacketSent) {
                                            firstPacketSent = true
                                            val firstData = if (bytesRead > 0) {
                                                buffer.copyOfRange(0, bytesRead)
                                            } else {
                                                ByteArray(0)
                                            }

                                            Log.d(LOG_TAG, "First packet for $destHost:$port - ${bytesRead} bytes")

                                            remoteSocket = layerMinus?.connectToLayerMinus(
                                                destHost,
                                                port.toString(),
                                                firstData
                                            )

                                            if (remoteSocket == null) {
                                                Log.e(LOG_TAG, "LayerMinus connection failed")
                                                client.close()
                                                break
                                            }

                                            // 启动反向转发

                                            // 先把所有需要的流拿到手，避免参数求值时触发 Socket 已关闭
                                            // ---- 启动 远端->客户端（读远端→写客户端）----
                                           val rs = remoteSocket!!
                                           val remoteIn  = BufferedInputStream(rs.getInputStream())
                                            val clientOut = client.getOutputStream()
                                           val remoteAlive =
                                               java.util.concurrent.atomic.AtomicBoolean(true)
                                           Thread {
                                                try {
                                                    forwardTraffic(remoteIn, clientOut)
                                                } finally {
                                                    // 标记远端读向已结束，并尽量让写端尽快退出
                                                    remoteAlive.set(false)
                                                    try { rs.shutdownOutput() } catch (_: Exception) {}
                                                }
                                            }.start()

											// 将标记存进 socket 的附加字段（简单起见放到 socket 属性上不做）
											// 后续写入前通过 rs.isClosed / isOutputShutdown + remoteAlive 来判断







                                        } else {
                                            val rs = remoteSocket
                                            if (rs == null) break
                                            // 若远端已关闭或停止输出，平滑退出
                                            if (rs.isClosed || rs.isOutputShutdown) {
                                               Log.d(LOG_TAG, "Remote socket closed/output shutdown; stop client->server")
                                                break
                                           }
                                           try {
                                               val out = rs.getOutputStream()
                                              out.write(buffer, 0, bytesRead)
                                                out.flush()
                                            } catch (se: SocketException) {
                                                val msg = se.message ?: ""
                                                // 常见正常收尾：对端先关、管道断、复位等
                                                if (msg.contains("Socket closed", true) ||
                                                    msg.contains("Broken pipe", true) ||
                                                    msg.contains("reset", true)) {
                                                    Log.d(LOG_TAG, "Client->server write ended (normal): $msg")
                                                    break
                                                } else {
                                                    throw se
                                                }
                                            }
                                        }
                                    }
                                } catch (e: Exception) {
                                    // 非致命：统一降级为 warn，避免误以为崩溃
                                    Log.w(LOG_TAG, "Client->server forward ended: ${e.message}")
                                } finally {
                                    remoteSocket?.close()
                                    client.close()
                                }
                            }.start()
                        } else {
                            // 直连模式
                            val target = Socket(destHost, port)
                            output.write(response)
                            output.flush()
                            forwardTraffic(input, target.getOutputStream())
                            forwardTraffic(target.getInputStream(), output)
                        }
                    }

                    0x03 -> { // UDP ASSOCIATE
                        handleSocks5UdpAssociate(client, output)
                    }

                    else -> {
                        output.write(byteArrayOf(0x05, 0x07)) // Command not supported
                        output.flush()
                        client.close()
                    }
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Error in handleSocks5", e)
                client.close()
            }
        }.start()

    }

    private enum class ProtocolType {
        TLS, HTTP, UNKNOWN
    }
    private data class ProtocolInfo(val type: ProtocolType, val details: String = "")
    private fun detectProtocol(data: ByteArray, port: Int): ProtocolInfo {
        // TLS 检测
        if (data.size >= 3 && data[0] == 0x16.toByte() && data[1] == 0x03.toByte()) {
            return ProtocolInfo(ProtocolType.TLS, "TLS ClientHello")
        }

        // HTTP 检测
        val httpMethods = listOf("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE ")
        if (data.size >= 4) {
            val header = String(data.take(16).toByteArray(), Charsets.UTF_8)
            for (method in httpMethods) {
                if (header.startsWith(method)) {
                    return ProtocolInfo(ProtocolType.HTTP, method.trim())
                }
            }
        }

        // 根据端口推断
        return when (port) {
            443, 8443 -> ProtocolInfo(ProtocolType.TLS, "Assumed by port")
            80, 8080 -> ProtocolInfo(ProtocolType.HTTP, "Assumed by port")
            else -> ProtocolInfo(ProtocolType.UNKNOWN)
        }
    }
    private fun rewriteHttpRequest(data: ByteArray, host: String, port: Int): ByteArray {
        // 如果 LayerMinus 需要特殊的 HTTP 请求格式，在这里重写
        // 目前看起来 LayerMinus 接受原始请求，所以可能不需要重写
        return data
    }

    private fun handleClient(client: Socket) {
        Thread {
            try {
                val input = BufferedInputStream(client.getInputStream())
                val output = client.getOutputStream()
                input.mark(4096)
                val version = input.read()
                input.reset()

                when (version) {
                    0x04 -> handleSocks4(client, input, output)
                    0x05 -> handleSocks5(client, input, output)
                    else -> {
                        val reader = BufferedReader(InputStreamReader(input))
                        var requestLine = reader.readLine()
                        Log.d(LOG_TAG, "HTTP/s forwarding ${requestLine}")
                        if (requestLine?.startsWith("CONNECT") == true) {
                            handleHttpsConnect(client, requestLine)
                        } else {
                            handleHttpProxy(client, requestLine, reader)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Error handling client", e)
                try {
                    client.close()
                } catch (_: Exception) {}
            }
        }.start()
    }



    override fun onDestroy() {
        isRunning = false
        serverThread?.interrupt()
        super.onDestroy()
        serverSocket?.close()
        Log.d(LOG_TAG, "onDestroy called")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotification(): Notification {
        return Notification.Builder(this, "SocketChannel")
            .setContentTitle("Socket Server Running")
            .setContentText("Listening on port 9000")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
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