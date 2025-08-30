package com.silentPass.vpn.vpn2socks

import android.util.Log
import java.io.EOFException
import java.net.InetSocketAddress
import java.net.Socket

data class SocksEndpoint(val host: String, val port: Int)

class SocksClient(private val endpoint: SocksEndpoint) {
    private val LOG_TAG = "SocksClient"

    fun dial(hostOrIp: String, port: Int): Socket {
        val s = Socket()

        // 连接到 SOCKS 服务器
        if (endpoint.host == "127.0.0.1" || endpoint.host == "localhost") {
            s.connect(InetSocketAddress(endpoint.host, endpoint.port), 5000)
        } else {
            Vpn2SocksService.protectSocket(s)
            s.connect(InetSocketAddress(endpoint.host, endpoint.port), 5000)
        }

        val out = s.getOutputStream()
        val inp = s.getInputStream()

        // SOCKS5 greeting
        out.write(byteArrayOf(0x05, 0x01, 0x00)) // Version 5, 1 method, No auth
        out.flush()

        // Read greeting response
        val greetingResp = ByteArray(2)
        var read = 0
        while (read < 2) {
            val r = inp.read(greetingResp, read, 2 - read)
            if (r < 0) {
                s.close()
                throw IllegalArgumentException("SOCKS greeting failed - EOF")
            }
            read += r
        }
        if (greetingResp[0] != 0x05.toByte() || greetingResp[1] != 0x00.toByte()) {
            s.close(); throw IllegalArgumentException("SOCKS greeting failed - invalid response")
        }

        // ！！！关键修复点：
        // 只做“字面量 IP”判断，绝不调用 getByName 去解析域名。
        val isIPv4Literal = hostOrIp.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$""")) &&
                hostOrIp.split('.').all { it.toInt() in 0..255 }
        val isIPv6Literal = hostOrIp.contains(':') // 简化判断即可；无需解析

        val req: ByteArray = when {
            isIPv4Literal && !isFakeIPv4Literal(hostOrIp) -> {
                android.util.Log.d(LOG_TAG, "Using IPv4 literal: $hostOrIp")
                val parts = hostOrIp.split('.').map { it.toInt().toByte() }.toByteArray()
                ByteArray(10).apply {
                    this[0] = 0x05; this[1] = 0x01; this[2] = 0x00; this[3] = 0x01 // ATYP=IPv4
                    System.arraycopy(parts, 0, this, 4, 4)
                    this[8] = ((port ushr 8) and 0xff).toByte()
                    this[9] = (port and 0xff).toByte()
                }
            }
            isIPv6Literal -> {
                android.util.Log.d(LOG_TAG, "Using IPv6 literal: $hostOrIp")
                val addr = java.net.InetAddress.getByName(hostOrIp).address
                ByteArray(22).apply {
                    this[0] = 0x05; this[1] = 0x01; this[2] = 0x00; this[3] = 0x04 // ATYP=IPv6
                    System.arraycopy(addr, 0, this, 4, 16)
                    this[20] = ((port ushr 8) and 0xff).toByte()
                    this[21] = (port and 0xff).toByte()
                }
            }
            else -> {
                // 默认严格使用“域名 ATYP”，避免任何本地解析（含 Fake-IP/普通域名）
                android.util.Log.d(LOG_TAG, "Using domain name (ATYP=0x03): $hostOrIp")
                val domainBytes = hostOrIp.encodeToByteArray()
                require(domainBytes.size <= 255) { "Domain too long for SOCKS5" }
                ByteArray(7 + domainBytes.size).apply {
                    this[0] = 0x05; this[1] = 0x01; this[2] = 0x00; this[3] = 0x03 // ATYP=域名
                    this[4] = domainBytes.size.toByte()
                    System.arraycopy(domainBytes, 0, this, 5, domainBytes.size)
                    this[5 + domainBytes.size] = ((port ushr 8) and 0xff).toByte()
                    this[6 + domainBytes.size] = (port and 0xff).toByte()
                }
            }
        }

        out.write(req)
        out.flush()

        // 读取 CONNECT 响应
        val hdr = ByteArray(4)
        read = 0
        while (read < 4) {
            val r = inp.read(hdr, read, 4 - read)
            if (r < 0) {
                s.close(); throw EOFException("SOCKS response incomplete - header")
            }
            read += r
        }
        if (hdr[1] != 0x00.toByte()) {
            val code = hdr[1].toInt() and 0xff
            val msg = when (code) {
                1 -> "general SOCKS server failure"
                2 -> "connection not allowed by ruleset"
                3 -> "network unreachable"
                4 -> "host unreachable"
                5 -> "connection refused"
                6 -> "TTL expired"
                7 -> "command not supported"
                8 -> "address type not supported"
                else -> "unknown error"
            }
            s.close(); throw IllegalArgumentException("SOCKS connect failed: $msg (code: $code)")
        }

        val atyp = hdr[3].toInt() and 0xff
        val remainingBytes = when (atyp) {
            0x01 -> 6
            0x03 -> {
                val lenByte = inp.read()
                if (lenByte < 0) { s.close(); throw EOFException("SOCKS response incomplete - domain length") }
                lenByte + 2
            }
            0x04 -> 18
            else -> { s.close(); throw IllegalArgumentException("Unknown ATYP in response: $atyp") }
        }
        val remaining = ByteArray(remainingBytes)
        read = 0
        while (read < remainingBytes) {
            val r = inp.read(remaining, read, remainingBytes - read)
            if (r < 0) { s.close(); throw EOFException("SOCKS response incomplete - address") }
            read += r
        }

        android.util.Log.d(LOG_TAG, "SOCKS connection established to $hostOrIp:$port")
        return s
    }

    // 198.18.0.0/15 的字面量判断（避免把 Fake-IP 当作 IPv4 ATYP 发送）
    private fun isFakeIPv4Literal(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size != 4) return false
        val a = parts[0].toIntOrNull() ?: return false
        val b = parts[1].toIntOrNull() ?: return false
        return a == 198 && (b == 18 || b == 19)
    }
}