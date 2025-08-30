package com.silentPass.vpn.vpn2socks

class FakeIPAllocator(ranges: List<IPv4Range>, private val reserved: Set<Int>) {
    private val ranges = ranges.toList()
    private var rangeIndex = 0
    private var next = ranges.first().start
    private val free = ArrayDeque<Int>()
    init { advance() }
    private fun advance() {
        while (rangeIndex < ranges.size) {
            val r = ranges[rangeIndex]
            if (next > r.end) { rangeIndex++; if (rangeIndex < ranges.size) next = ranges[rangeIndex].start; continue }
            if (reserved.contains(next)) { next++; continue }
            break
        }
    }
    fun pushBack(ip: Int) { if (!reserved.contains(ip)) free.addLast(ip) }
    fun allocate(): IPv4Address? {
        if (free.isNotEmpty()) return IPv4Address(free.removeLast())
        if (rangeIndex >= ranges.size) return null
        val out = next
        next++
        advance()
        return IPv4Address(out)
    }
}