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

class SocketServerService : Service() {

    private var serverThread: Thread? = null
    private var isRunning = true
    private var layerMinus: LayerMinus? = null
    private var serverSocket: ServerSocket? = null

    private fun forwardTraffic(input: InputStream, output: OutputStream) {
        Thread {
            try {
                val buffer = ByteArray(4096)
                var bytes: Int
                while (input.read(buffer).also { bytes = it } != -1) {
                    output.write(buffer, 0, bytes)
                    output.flush()
                }
            } catch (_: Exception) {
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
                this.layerMinus = LayerMinus(startVPNData)

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
        Log.d("SocketServerService", "Service created")
    }

    private fun handleHttpProxy(client: Socket, requestLine: String?, reader: BufferedReader) {
        Thread {
            if (requestLine == null) {
                Log.e("HTTP Proxy", "Null request line")
                client.close()
                return@Thread
            }

            try {
                Log.d("HTTP Proxy", "Request Line: $requestLine")

                val headers = mutableListOf<String>()
                var line: String?
                while (reader.readLine().also { line = it } != null && line!!.isNotEmpty()) {
                    headers.add(line!!)
                }

                val parts = requestLine.split(" ")

                if (parts.size < 3) {
                    Log.e("HTTP Proxy", "Invalid request line")
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

                Log.d("HTTP Proxy", "Target: $host:$port$path")

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
                requestBody += "\r\n" + body

                val serverSocket: Socket?
                if (layerMinus != null) {

                                ""
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
                Log.e("HTTP Proxy", "Error: ${e.message}", e)
                try {
                    client.close()
                } catch (_: Exception) {}
            }
        }.start()
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
                    val buffer = ByteArray(4096)
                    val output = ByteArrayOutputStream()
                    var bytesRead: Int
                    inputStream.read(buffer).also { bytesRead = it }
                    output.write(buffer, 0, bytesRead)

                    val rawBytes = output.toByteArray()

                    Log.d("handleHttpsConnect", "rawBytes length = ${bytesRead}")
                    var serverSocket =
                        layerMinus?.connectToLayerMinus(host, port.toString(), rawBytes)
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
                    "ProxyServer",
                    "try lauer minus data ${this.layerMinus?.entryNodes[0]?.country}"
                )
                    }

            } catch (e: Exception) {
                Log.e("ProxyServer", "HTTPS CONNECT failed", e)
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
                output.write(response)
                output.flush()
                val inputStream: InputStream = client.getInputStream()
                val buffer = ByteArray(4096)
                val output = ByteArrayOutputStream()
                var bytesRead: Int
                inputStream.read(buffer).also { bytesRead = it }
                output.write(buffer, 0, bytesRead)

                val rawBytes = output.toByteArray()

                Log.d("handleHttpsConnect", "rawBytes length = ${bytesRead}")
                var serverSocket =
                    layerMinus?.connectToLayerMinus(destHost, port.toString(), rawBytes)
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
                    Log.e("SOCKS4", "Connection error", e)
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
            Log.e("SOCKS5", "UDP associate failed", e)
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
                    0x01 -> { // CONNECT (handled before)


                        if (layerMinus != null) {

                            output.write(response)
                            output.flush()

                            val inputStream: InputStream = client.getInputStream()
                            val buffer = ByteArray(4096)
                            val output = ByteArrayOutputStream()
                            var bytesRead: Int
                            inputStream.read(buffer).also { bytesRead = it }
                            output.write(buffer, 0, bytesRead)

                            val rawBytes = output.toByteArray()

                            Log.d("handleHttpsConnect", "rawBytes length = ${bytesRead}")
                            var serverSocket =
                                layerMinus?.connectToLayerMinus(destHost, port.toString(), rawBytes)
                            if (serverSocket == null) {
                                client.close()
                                return@Thread
                            }

                            val serverInput = BufferedInputStream(serverSocket.getInputStream())
                            val clientOutput = client.getOutputStream()
                            forwardTraffic(serverInput, clientOutput)
                            forwardTraffic(client.getInputStream(), serverSocket.getOutputStream())

                        } else {

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
                Log.e("SOCKS5", "Error", e)
                client.close()
            }
        }.start()
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
                        Log.d("ProxyServer", "HTTP/s forwarding ${requestLine}")
                        if (requestLine?.startsWith("CONNECT") == true) {
                            handleHttpsConnect(client, requestLine)
                        } else {
                            handleHttpProxy(client, requestLine, reader)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("Proxy", "Error handling client", e)
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
        Log.d("WebAppInterface", "onDestroy called")
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