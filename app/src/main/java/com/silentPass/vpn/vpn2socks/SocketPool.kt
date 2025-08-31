package com.silentPass.vpn.vpn2socks

import java.net.Socket
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import android.util.Log
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap

object SocketPool {

    init {
        Log.d("SocketPool", "SocketPool singleton initialized")
    }
    private const val LOG_TAG = "SocketPool"
    private const val MAX_IDLE_SOCKETS = 20
    private const val MAX_ACTIVE_SOCKETS = 100

    private val idlePool = ConcurrentLinkedQueue<Socket>()
    private val activeCount = AtomicInteger(0)
    private val activeSockets = Collections.newSetFromMap(ConcurrentHashMap<Socket, Boolean>())

    // 添加统计信息
    private val totalAcquired = AtomicInteger(0)
    private val totalReleased = AtomicInteger(0)
    private val totalReused = AtomicInteger(0)

    fun acquire(): Socket {
        // 先尝试从池中获取
        var socket = idlePool.poll()

        if (socket != null && !socket.isClosed) {
            activeSockets.add(socket)
            activeCount.incrementAndGet()
            totalReused.incrementAndGet()
            totalAcquired.incrementAndGet()
            Log.d(LOG_TAG, "Reused socket from pool (active: ${activeCount.get()}, idle: ${idlePool.size})")
            return socket
        }

        // 创建新Socket
        if (activeCount.get() < MAX_ACTIVE_SOCKETS) {
            socket = Socket()
            activeSockets.add(socket)
            activeCount.incrementAndGet()
            totalAcquired.incrementAndGet()
            Log.d(LOG_TAG, "Created new socket (active: ${activeCount.get()})")
            return socket
        }

        throw IllegalStateException("Socket pool exhausted: ${activeCount.get()} active")
    }

    fun release(socket: Socket) {
        val wasActive = activeSockets.remove(socket)
        if (wasActive) {
            activeCount.decrementAndGet()
            totalReleased.incrementAndGet()
        }

        if (!socket.isClosed && idlePool.size < MAX_IDLE_SOCKETS) {
            try {
                socket.soTimeout = 0  // 重置超时
                idlePool.offer(socket)
                Log.d(LOG_TAG, "Socket returned to pool (active: ${activeCount.get()}, idle: ${idlePool.size})")
            } catch (e: Exception) {
                Log.w(LOG_TAG, "Failed to return socket to pool: ${e.message}")
                closeQuietly(socket)
            }
        } else {
            closeQuietly(socket)
        }
    }

    private fun closeQuietly(socket: Socket) {
        try {
            socket.close()
        } catch (_: Exception) {}
    }

    fun cleanup() {
        // 定期清理空闲连接
        val toRemove = mutableListOf<Socket>()
        idlePool.forEach { socket ->
            if (socket.isClosed) toRemove.add(socket)
        }
        toRemove.forEach { idlePool.remove(it) }

        // 输出统计信息
        Log.d(LOG_TAG, "Pool stats - Active: ${activeCount.get()}, Idle: ${idlePool.size}, " +
                "Total acquired: ${totalAcquired.get()}, Released: ${totalReleased.get()}, " +
                "Reused: ${totalReused.get()}")
    }

    // 强制清理所有连接（应用退出时调用）
    fun shutdown() {
        activeSockets.forEach { closeQuietly(it) }
        activeSockets.clear()

        while (idlePool.isNotEmpty()) {
            closeQuietly(idlePool.poll())
        }

        activeCount.set(0)
        Log.d(LOG_TAG, "Socket pool shutdown complete")
    }
}