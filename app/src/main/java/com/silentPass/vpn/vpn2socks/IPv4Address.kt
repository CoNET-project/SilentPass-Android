package com.silentPass.vpn.vpn2socks

data class IPv4Address(val raw: Int) {
    override fun toString(): String = listOf(
        (raw ushr 24) and 0xff,
        (raw ushr 16) and 0xff,
        (raw ushr 8) and 0xff,
        raw and 0xff
    ).joinToString(".")


    companion object {
        fun parse(s: String): IPv4Address? {
            val parts = s.split('.')
            if (parts.size != 4) return null
            val b = parts.map { it.toInt() and 0xff }
            val v = (b[0] shl 24) or (b[1] shl 16) or (b[2] shl 8) or b[3]
            return IPv4Address(v)
        }
    }
}