package com.silentPass.vpn.vpn2socks

class IPv4Range(cidr: String) {
    val start: Int
    val end: Int // inclusive
    init {
        val parts = cidr.split('/')
        require(parts.size == 2)
        val prefix = parts[1].toInt()
        val base = IPv4Address.parse(parts[0])!!.raw
        val hostBits = 32 - prefix
        val mask = if (hostBits == 32) 0 else (0xffffffff.toInt() shl hostBits)
        val network = base and mask
        val broadcast = network or mask.inv()
        start = network
        end = broadcast
    }
    fun contains(ip: Int) = ip in start..end
}