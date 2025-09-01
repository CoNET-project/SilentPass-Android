package com.silentPass.vpn

import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.web3j.crypto.Credentials
import org.web3j.crypto.Hash
import org.web3j.crypto.Sign
import org.web3j.utils.Numeric
import java.io.BufferedWriter
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.UUID



object LayerMinus {

    // ---- 全局共享状态（单例） ----
    @Volatile private var initialized = false
    private lateinit var credentials: Credentials
    lateinit var entryNodes: List<Node>
        private set
    lateinit var exitNode: List<Node>
        private set
    val jsonGson = Gson()

    private const val CONNECT_TIMEOUT_MS = 5_000

    private const val ENTRY_DISABLE_MS = 5 * 60 * 1000 // 5 分钟

    @Synchronized
    fun init(startVPNData: StartVPNData) {
        credentials = Credentials.create(startVPNData.privateKey.removePrefix("0x"))
        entryNodes = startVPNData.entryNodes
        exitNode = startVPNData.exitNode
        initialized = true
        Log.i("LayerMinus", "Initialized: entries=${entryNodes.size}, exits=${exitNode.size}")
    }


    private val disabledEntryUntilMs = java.util.concurrent.ConcurrentHashMap<String, Long>()

    private fun ensureInitialized() {
        check(initialized) { "LayerMinus not initialized. Call LayerMinus.init(startVPNData) first." }
    }

    private fun now() = System.currentTimeMillis()

    private fun isEntryAvailable(ip: String): Boolean {
        val until = disabledEntryUntilMs[ip] ?: return true
        if (until <= now()) {
            disabledEntryUntilMs.remove(ip)
            return true
        }
        return false
    }

    private fun markEntryTimeout(ip: String) {
        disabledEntryUntilMs[ip] = now() + ENTRY_DISABLE_MS
        Log.w("LayerMinus", "Entry node $ip 超时，禁用 5 分钟")
    }



    fun getKeyIdFromArmoredPublicKey(armoredPublicKey: String): Long {
        val publicKeyRing = PGPainless.readKeyRing()
            .publicKeyRing(ByteArrayInputStream(armoredPublicKey.toByteArray(Charsets.UTF_8)))!!

        val primaryKey = publicKeyRing.publicKey
        return primaryKey.keyID
    }


    private fun postEncryptedPGPMessage(host: String, pgpMessage: String): Socket {
        val socket = Socket()
        socket.connect(InetSocketAddress(host, 80), CONNECT_TIMEOUT_MS)
        val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream(), Charsets.UTF_8))

        val path = "/post"
        val contentLength = pgpMessage.toByteArray(Charsets.UTF_8).size

        // Step 1: Write HTTP POST request
        writer.write("POST $path HTTP/1.1\r\n")
        writer.write("Host: $host\r\n")
        writer.write("Content-Type: application/json;charset=UTF-8\r\n")
        writer.write("Connection: keep-alive\r\n")
        writer.write("Content-Length: $contentLength\r\n")
        writer.write("\r\n") // End of headers
        writer.write(pgpMessage) // Body
        writer.flush()
        return socket
    }

    fun encryptWithArmoredPublicKey(message: String, armoredPublicKey: String): String {
        val byteOutput = ByteArrayOutputStream()
        val publicKeyRing = PGPainless.readKeyRing()
            .publicKeyRing(ByteArrayInputStream(armoredPublicKey.toByteArray(StandardCharsets.UTF_8)))
        if (publicKeyRing != null) {
            val encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(byteOutput)
                .withOptions(
                    ProducerOptions.encrypt(
                        EncryptionOptions()
                            .addRecipient(publicKeyRing)
                            .overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_192),

                    ).setAsciiArmor(true)
                )
            encryptionStream.write(message.toByteArray(StandardCharsets.UTF_8))
            encryptionStream.close()
            encryptionStream.getResult()
            val result = byteOutput.toString(StandardCharsets.UTF_8.name())

            return result
        }
        return ""
    }

    fun createSock5ConnectCmd (connectData: VE_IPptpStream): String {
        val secureRandom = SecureRandom()
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)

        val command = SICommandObj(
            command = "SaaS_Sock5",
            algorithm = "aes-256-cbc",
            Securitykey = bytes.toString(),
            requestData = listOf(connectData),
            walletAddress = credentials.address
        )
        val jsonString = Gson().toJson(command)
        val jsonBytes = jsonString.toByteArray(Charsets.UTF_8)

        if (jsonBytes != null) {
            val messageHash = Hash.sha3(jsonBytes)
            val signatureData = Sign.signMessage(jsonBytes, credentials.ecKeyPair)

            val r = Numeric.toHexString(signatureData.r)
            val s = Numeric.toHexString(signatureData.s)
            val v = Numeric.toHexString(signatureData.v)

            val signatureHex = r + s.drop(2) + v.drop(2)
            val request = requestData (
                message = jsonString,
                signMessage = signatureHex
            )
            return Gson().toJson(request)
        }
        return ""

    }

    fun connectToLayerMinus(host: String, _port: String, buffer: ByteArray?): Socket? {
        val availableEntries = this.entryNodes.filter { isEntryAvailable(it.ip_addr) }
        if (availableEntries.isEmpty()) {
            Log.e("LayerMinus", "没有可用的 entryNodes（全部处于禁用期）")
            return null
        }
        val randomEntryNode = availableEntries.random()

        val randomExitNode = if (this.exitNode.isNotEmpty()) {
            this.exitNode.random()
        } else {
            return null // or throw Exception("No entry nodes available")
        }


        val port = _port ?: "80"

        val base64String = buffer?.let {
            Base64.encodeToString(buffer, Base64.NO_WRAP)
        } ?: ""

        val connectData = VE_IPptpStream(
            host = host,
            port = port,
            buffer = base64String,
            uuid = UUID.randomUUID().toString()
        )

        val cmd = createSock5ConnectCmd(connectData)
        val base64Cmd = cmd?.let {
            val byteArray = cmd.toByteArray(Charsets.UTF_8)
            Base64.encodeToString(byteArray, Base64.NO_WRAP)
        } ?: ""

        if (base64Cmd.length == 0) {
            return null
        }
        val requestData = encryptWithArmoredPublicKey(base64Cmd, randomExitNode.armoredPublicKey)
        val jsonbPost = postHttp(
            data = requestData
        )
        val _postData = this.jsonGson.toJson(jsonbPost)
        Log.d("WebAppInterface", "connectToLayerMinus Entry Node ${randomEntryNode.ip_addr}:80 Exit Node ${randomExitNode.ip_addr}")

        if (_postData.isNotEmpty()) {
            try {
                return postEncryptedPGPMessage(randomEntryNode.ip_addr, _postData)
            } catch (e: SocketTimeoutException) {
                // 连接超时：禁用该 entry 节点 5 分钟
                markEntryTimeout(randomEntryNode.ip_addr)
                Log.e("LayerMinus", "连接 entryNode 超时: ${randomEntryNode.ip_addr}", e)
                return null
            } catch (e: IOException) {
                // 其他 IO 异常不自动禁用，只记录（如需也禁用，可改为调用 markEntryTimeout）
                Log.e("LayerMinus", "连接 entryNode 失败: ${randomEntryNode.ip_addr}", e)
                return null
            }

        }
        return null
    }
}