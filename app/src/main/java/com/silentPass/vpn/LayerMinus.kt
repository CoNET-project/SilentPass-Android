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
import java.io.OutputStreamWriter
import java.net.Socket
import java.net.InetSocketAddress
import java.nio.channels.SocketChannel
import java.nio.channels.Channels
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.UUID
import java.nio.channels.Selector
import java.nio.channels.SelectionKey


data class LmPlan(
    val entryHost: String,      // 入口节点（B）
    val entryPort: Int,         // 一般 80/443，按你的入口配置
    val destHost: String,       // 目标 D（仅用于日志/可选）
    val destPort: Int,
    val packedFirstData: ByteArray // 第一拍要发给入口 B 的完整字节（含HTTP头+PGP JSON）
)


class LayerMinus(startVPNData: StartVPNData) {
	val path = "/post"
	private fun makeHttpPost(host: String, bodyUtf8: String): ByteArray {
		val body = bodyUtf8.toByteArray(Charsets.UTF_8)
		val sb = StringBuilder()
		sb.append("POST ").append(path).append(" HTTP/1.1\r\n")
		.append("Host: ").append(host).append("\r\n")
		.append("Content-Type: application/json\r\n")
		.append("Content-Length: ").append(body.size).append("\r\n")
		.append("Connection: keep-alive\r\n")
		.append("\r\n")
		val head = sb.toString().toByteArray(Charsets.UTF_8)
		return head + body
	}

	// 与 SocketServerService 一致的轻量 socket 调优
    private fun tuneSocket(ch: SocketChannel) {
        try { ch.socket().tcpNoDelay = true } catch (_: Exception) {}
        try { ch.socket().keepAlive = true } catch (_: Exception) {}
        try { ch.socket().setSoLinger(false, 0) } catch (_: Exception) {} // 避免主动 close 触发 RST
    }


    private val credentials: Credentials = Credentials.create(
        startVPNData.privateKey.removePrefix("0x")
    )

    val entryNodes = startVPNData.entryNodes
    val exitNode = startVPNData.exitNode
    val jsonGson = Gson()

    fun getKeyIdFromArmoredPublicKey(armoredPublicKey: String): Long {
        val publicKeyRing = PGPainless.readKeyRing()
            .publicKeyRing(ByteArrayInputStream(armoredPublicKey.toByteArray(Charsets.UTF_8)))!!

        val primaryKey = publicKeyRing.publicKey
        return primaryKey.keyID
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

    fun connectToLayerMinus(host: String, _port: String, buffer: ByteArray?): LmPlan? {

        val randomEntryNode = if (this.entryNodes.isNotEmpty()) {
//            this.entryNodes[0]
            this.entryNodes.random()
        } else {
            return null // or throw Exception("No entry nodes available")
        }

        val randomExitNode = if (this.exitNode.isNotEmpty()) {
//            this.exitNode[0]
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
            val packed = makeHttpPost(randomEntryNode.ip_addr, _postData)
			return LmPlan(
                entryHost = randomEntryNode.ip_addr, // 入口节点B
                entryPort = 80,                      // 你现在固定用的端口；如有配置可替换
                destHost = host,                     // 目标D（用于日志/观测）
                destPort = port.toInt(),
                packedFirstData = packed             // 第一拍发给入口B的整段字节(HTTP POST+PGP JSON)
            )
        }


        return null
    }


}