package com.silentPass.vpn.vpn2socks

class IPv4Packet(val raw: ByteArray) {
    val ihlBytes: Int
    val proto: Int
    val src: IPv4Address
    val dst: IPv4Address
    val payload: ByteArray

    init {


        require(raw.size >= 20) { "IPv4: totalLen < 20" }
        val version = (raw[0].toInt() ushr 4) and 0x0f
        require(version == 4) { "Not IPv4: version=$version" }

        ihlBytes = (raw[0].toInt() and 0x0f) * 4
        require(ihlBytes >= 20 && raw.size >= ihlBytes) { "IPv4: bad IHL or short header" }

        proto = raw[9].toInt() and 0xff
        val s = ((raw[12].toInt() and 0xff) shl 24) or ((raw[13].toInt() and 0xff) shl 16) or ((raw[14].toInt() and 0xff) shl 8) or (raw[15].toInt() and 0xff)
        val d = ((raw[16].toInt() and 0xff) shl 24) or ((raw[17].toInt() and 0xff) shl 16) or ((raw[18].toInt() and 0xff) shl 8) or (raw[19].toInt() and 0xff)
        src = IPv4Address(s)
        dst = IPv4Address(d)
        payload = raw.copyOfRange(ihlBytes, raw.size)
    }
}