package com.silentPass.vpn.vpn2socks

class UDPDatagram(data: ByteArray) {
    val srcPort: Int
    val dstPort: Int
    val payload: ByteArray
    init {
        require(data.size >= 8)
        srcPort = ((data[0].toInt() and 0xff) shl 8) or (data[1].toInt() and 0xff)
        dstPort = ((data[2].toInt() and 0xff) shl 8) or (data[3].toInt() and 0xff)
        payload = data.copyOfRange(8, data.size)
    }
}