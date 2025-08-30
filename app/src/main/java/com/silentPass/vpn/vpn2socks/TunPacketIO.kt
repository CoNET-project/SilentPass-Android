package com.silentPass.vpn.vpn2socks

import android.os.ParcelFileDescriptor
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import okio.Buffer
import okio.Source
import okio.sink
import okio.source
import java.io.FileInputStream
import java.io.FileOutputStream

class TunPacketIO(private val tunFd: ParcelFileDescriptor) {
    data class TunPacket(val bytes: ByteArray, val length: Int)

    private val input = FileInputStream(tunFd.fileDescriptor)
    private val output = FileOutputStream(tunFd.fileDescriptor)

    val readerChannel = Channel<TunPacket>(Channel.UNLIMITED)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    init { scope.launch { readLoop() } }

    private suspend fun readLoop() {
        val buf = ByteArray(65536)
        while (currentCoroutineContext().isActive) {
            val n = withContext(Dispatchers.IO) { input.read(buf) }
            if (n > 0) {
                // 拷贝一份正确长度的数据，避免后续复用缓冲导致脏读
                readerChannel.send(TunPacket(buf.copyOf(n), n))
            }
        }
    }

    fun writePackets(packets: List<ByteArray>, protos: List<Int>) {
        for (p in packets) output.write(p)
        output.flush()
    }
}