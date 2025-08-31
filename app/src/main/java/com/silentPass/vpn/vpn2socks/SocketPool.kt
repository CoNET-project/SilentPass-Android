package com.silentPass.vpn.vpn2socks

import java.net.Socket
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import android.util.Log
import java.util.Collections
import java.util.LinkedList
import java.util.WeakHashMap
import java.util.concurrent.ConcurrentHashMap

object SocketPool {

    private val pool = LinkedList<Socket>()
    private val activeConnections = WeakHashMap<Socket, Long>()
    private val maxPoolSize = 10
    private val maxIdleTime = 30_000L // 30秒

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

    @Synchronized
    fun acquire(): Socket {
        // 清理过期的socket
        cleanupStale()

        val socket = pool.pollFirst() ?: Socket()
        activeConnections[socket] = System.currentTimeMillis()
        return socket
    }

    @Synchronized
    fun release(socket: Socket?) {
        socket ?: return

        activeConnections.remove(socket)

        try {
            if (!socket.isClosed && pool.size < maxPoolSize) {
                pool.offer(socket)
            } else {
                socket.close()
            }
        } catch (e: Exception) {
            socket.runCatching { close() }
        }
    }

    private fun closeQuietly(socket: Socket) {
        try {
            socket.close()
        } catch (_: Exception) {}
    }

    @Synchronized
    fun cleanup() {
        // 清理池中的socket
        val iter = pool.iterator()
        while (iter.hasNext()) {
            val socket = iter.next()
            if (socket.isClosed) {
                iter.remove()
            }
        }

        // 清理泄漏的活跃连接（超过60秒未归还）
        val now = System.currentTimeMillis()
        activeConnections.entries.removeIf { (socket, time) ->
            if (now - time > 60_000) {
                Log.w("SocketPool", "Force closing leaked socket")
                socket.runCatching { close() }
                true
            } else {
                false
            }
        }
    }

    private fun cleanupStale() {
        val now = System.currentTimeMillis()
        pool.removeIf { socket ->
            socket.isClosed || (now - (activeConnections[socket] ?: 0) > maxIdleTime)
        }
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