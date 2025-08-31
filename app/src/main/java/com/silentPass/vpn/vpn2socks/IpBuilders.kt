package com.silentPass.vpn.vpn2socks

import java.nio.ByteBuffer

private fun ipChecksum(hdr: ByteArray): Short {
    var sum = 0L
    var i = 0
    while (i < hdr.size) {
        val v = ((hdr[i].toInt() and 0xff) shl 8) + (hdr[i+1].toInt() and 0xff)
        sum += v
        i += 2
    }
    while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
    return ((sum.inv() and 0xffff).toInt()).toShort()
}

private fun pseudoHeaderSum(src: Int, dst: Int, proto: Int, len: Int): Long {
    var sum = 0L
    // src
    sum += (src ushr 16) and 0xffff; sum += src and 0xffff
    // dst
    sum += (dst ushr 16) and 0xffff; sum += dst and 0xffff
    // proto + length
    sum += proto and 0xff
    sum += len and 0xffff
    return sum
}

private fun checksumWithPseudo(ps: Long, data: ByteArray): Short {
    var sum = ps
    var i = 0
    while (i + 1 < data.size) {
        val v = ((data[i].toInt() and 0xff) shl 8) + (data[i+1].toInt() and 0xff)
        sum += v
        i += 2
    }
    if (i < data.size) sum += (data[i].toInt() and 0xff) shl 8
    while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
    return ((sum.inv() and 0xffff).toInt()).toShort()
}

object IpBuilders {
    fun udpFrom(src: IPv4Address, dst: IPv4Address, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val ipHdr = 20; val udpHdr = 8
        val total = ipHdr + udpHdr + payload.size
        val bb = ByteBuffer.allocate(total)

        // IPv4 header
        bb.put(0x45.toByte()); bb.put(0) // ver/ihl + tos
        bb.putShort(total.toShort())
        bb.putShort(0); bb.putShort(0x4000.toShort()) // id + flags/frag
        bb.put(64.toByte()); bb.put(17.toByte()); bb.putShort(0) // ttl + proto + csum(0)
        bb.putInt(src.raw); bb.putInt(dst.raw)

        // UDP
        bb.putShort(srcPort.toShort()); bb.putShort(dstPort.toShort())
        bb.putShort((udpHdr + payload.size).toShort()); bb.putShort(0)
        bb.put(payload)

        // fill UDP checksum
        val arr = bb.array()
        val udpOff = ipHdr
        val ps = pseudoHeaderSum(src.raw, dst.raw, 17, udpHdr + payload.size)
        val udpCsum = checksumWithPseudo(ps, arr.copyOfRange(udpOff, udpOff + udpHdr + payload.size))
        arr[udpOff + 6] = (udpCsum.toInt() ushr 8).toByte()
        arr[udpOff + 7] = (udpCsum.toInt() and 0xff).toByte()

        // fill IP checksum
        val ipCsum = ipChecksum(arr.copyOfRange(0, ipHdr))
        arr[10] = (ipCsum.toInt() ushr 8).toByte()
        arr[11] = (ipCsum.toInt() and 0xff).toByte()
        return arr
    }

    fun icmpPortUnreachable(ip: IPv4Packet): ByteArray {
        val icmpHdr = 8
        val icmpPayload = ip.raw.copyOfRange(0, ip.ihlBytes + 8)
        val icmp = ByteArray(icmpHdr + icmpPayload.size)
        icmp[0] = 3; icmp[1] = 3 // type/code
        // checksum later
        // 4 bytes zero
        System.arraycopy(icmpPayload, 0, icmp, 8, icmpPayload.size)

        // fill ICMP checksum
        val csum = ipChecksum(icmp)
        icmp[2] = (csum.toInt() ushr 8).toByte(); icmp[3] = (csum.toInt() and 0xff).toByte()

        // wrap to IPv4
        val ipHdr = 20
        val total = ipHdr + icmp.size
        val bb = ByteBuffer.allocate(total)
        bb.put(0x45.toByte()); bb.put(0); bb.putShort(total.toShort()); bb.putShort(0)
        bb.putShort(0x4000.toShort()); bb.put(64.toByte()); bb.put(1.toByte()); bb.putShort(0)
        bb.putInt(ip.dst.raw); bb.putInt(ip.src.raw)
        bb.put(icmp)

        val arr = bb.array()
        val ipCsum = ipChecksum(arr.copyOfRange(0, ipHdr))
        arr[10] = (ipCsum.toInt() ushr 8).toByte()
        arr[11] = (ipCsum.toInt() and 0xff).toByte()
        return arr
    }

    // 原始方法保持兼容性
    fun tcpPayloadFromServer(src: IPv4Address, dst: IPv4Address, srcPort: Int, dstPort: Int, payload: ByteArray,
                             seq: Int, ack: Int, flags: Int = 0x18, window: Int = 65535): ByteArray {
        return tcpPayloadFromServerWithOptions(src, dst, srcPort, dstPort, payload, seq, ack, flags, window, null)
    }

    // 新方法：支持TCP选项
    fun tcpPayloadFromServerWithOptions(
        src: IPv4Address, dst: IPv4Address,
        srcPort: Int, dstPort: Int,
        payload: ByteArray,
        seq: Int, ack: Int,
        flags: Int = 0x18,
        window: Int = 65535,
        tcpOptions: ByteArray? = null
    ): ByteArray {
        val ipHdr = 20

        // 计算TCP选项的填充
        var optionsWithPadding = tcpOptions ?: ByteArray(0)
        if (optionsWithPadding.isNotEmpty()) {
            // TCP选项必须是4字节对齐
            val optLen = optionsWithPadding.size
            val padding = (4 - (optLen % 4)) % 4
            if (padding > 0) {
                optionsWithPadding = optionsWithPadding + ByteArray(padding) // NOP padding
            }
        }

        val tcpHdr = 20 + optionsWithPadding.size
        val total = ipHdr + tcpHdr + payload.size
        val bb = ByteBuffer.allocate(total)

        // IPv4 header
        bb.put(0x45.toByte()); bb.put(0); bb.putShort(total.toShort()); bb.putShort(0)
        bb.putShort(0x4000.toShort()); bb.put(64.toByte()); bb.put(6.toByte()); bb.putShort(0)
        bb.putInt(src.raw); bb.putInt(dst.raw)

        // TCP header
        bb.putShort(srcPort.toShort()); bb.putShort(dstPort.toShort())
        bb.putInt(seq); bb.putInt(ack)

        // Data offset (header length in 32-bit words)
        val dataOffset = tcpHdr / 4
        bb.put((dataOffset shl 4).toByte()); bb.put(flags.toByte())
        bb.putShort(window.toShort()); bb.putShort(0); bb.putShort(0) // csum=0, urg=0

        // TCP options
        if (optionsWithPadding.isNotEmpty()) {
            bb.put(optionsWithPadding)
        }

        // Payload
        bb.put(payload)

        val arr = bb.array()

        // TCP checksum with pseudo header
        val ps = pseudoHeaderSum(src.raw, dst.raw, 6, tcpHdr + payload.size)
        val tcpCsum = checksumWithPseudo(ps, arr.copyOfRange(ipHdr, total))
        arr[ipHdr + 16] = (tcpCsum.toInt() ushr 8).toByte()
        arr[ipHdr + 17] = (tcpCsum.toInt() and 0xff).toByte()

        // IP checksum
        val ipCsum = ipChecksum(arr.copyOfRange(0, ipHdr))
        arr[10] = (ipCsum.toInt() ushr 8).toByte()
        arr[11] = (ipCsum.toInt() and 0xff).toByte()

        return arr
    }

    // 用于SYN-ACK的特殊版本，支持MSS和SACK-Permitted选项
    fun tcpSynAckWithOptions(
        src: IPv4Address, dst: IPv4Address,
        srcPort: Int, dstPort: Int,
        seq: Int, ack: Int,
        window: Int = 65535,
        mss: Int = 1460,
        sackPermitted: Boolean = true
    ): ByteArray {
        val options = mutableListOf<Byte>()

        // MSS option (kind=2, length=4)
        options.add(2)
        options.add(4)
        options.add((mss shr 8).toByte())
        options.add((mss and 0xFF).toByte())

        // SACK-Permitted option (kind=4, length=2)
        if (sackPermitted) {
            options.add(4)
            options.add(2)
        }

        // NOP padding for alignment if needed
        while (options.size % 4 != 0) {
            options.add(1) // NOP
        }

        return tcpPayloadFromServerWithOptions(
            src, dst, srcPort, dstPort,
            ByteArray(0), // No payload for SYN-ACK
            seq, ack,
            0x12, // SYN | ACK flags
            window,
            options.toByteArray()
        )
    }
}