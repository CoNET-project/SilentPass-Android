package com.silentPass.vpn.vpn2socks

class TCPSegment(data: ByteArray) {
    val raw: ByteArray = data               // ← 新增：让上层能读到完整原始TCP字节
    val srcPort: Int
    val dstPort: Int
    val seq: Long
    val ack: Long
    val flags: Int
    val headerLen: Int
    val payload: ByteArray
    init {
        require(data.size >= 20)
        fun be16(off: Int) = (((data[off].toInt() and 0xff) shl 8) or (data[off + 1].toInt() and 0xff))
        fun be32(off: Int) = ((be16(off) shl 16) or be16(off + 2))
        srcPort = be16(0)
        dstPort = be16(2)
        seq = be32(4).toLong() and 0xffffffffL
        ack = be32(8).toLong() and 0xffffffffL
        val off = (data[12].toInt() ushr 4) and 0x0f
        headerLen = off * 4
        flags = data[13].toInt() and 0xff
        payload = data.copyOfRange(headerLen, data.size)
    }
    val isSYN get() = (flags and 0x02) != 0
    val isACK get() = (flags and 0x10) != 0
    val isFIN get() = (flags and 0x01) != 0
    val isRST get() = (flags and 0x04) != 0
}