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
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.UUID


data class Node (
    val country: String,
    val ip_addr: String,
    val region: String,
    val armoredPublicKey: String,
    val nftNumber: String
)

data class StartVPNData(
    val entryNodes: List<Node>,
    val exitNode: List<Node>,
    val privateKey: String
)

data class VE_IPptpStream (
    val host: String,
    val port: String,
    val buffer: String,
    val uuid: String
)

data class SICommandObj (
    val command: String,
    val algorithm: String,
    val Securitykey: String,
    val requestData: List<VE_IPptpStream>,
    val walletAddress: String
)

data class requestData (
    val message: String,
    val signMessage: String
)

data class postHttp (
    val data: String
)

class LayerMinus(startVPNData: StartVPNData) {
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

    fun postEncryptedPGPMessage(host: String, pgpMessage: String): Socket {
        val socket = Socket(host, 80)
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
        Log.d("WebAppInterface", "$cmd")
        val requestData = encryptWithArmoredPublicKey(base64Cmd, randomExitNode.armoredPublicKey)
        val jsonbPost = postHttp(
            data = requestData
        )
        val _postData = this.jsonGson.toJson(jsonbPost)
        Log.d("WebAppInterface", "connectToLayerMinus Entry Node ${randomEntryNode.ip_addr} Exit Node ${randomExitNode.ip_addr} \n${jsonbPost}")

        if (_postData.isNotEmpty()) {
            return postEncryptedPGPMessage(randomEntryNode.ip_addr, _postData)
        }
        return null
    }
}