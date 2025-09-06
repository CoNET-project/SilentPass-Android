package com.silentPass.vpn.vpn2socks

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

object OverlayGate {
    private val ref = AtomicReference(CountDownLatch(1))
    @Volatile private var ready = false

    fun reset() {
        ready = false
        ref.set(CountDownLatch(1))
    }

    fun signalReady() {
        if (!ready) {
            ready = true
            ref.get().countDown()
        }
    }

    /** 在首次外连前最多等 timeoutMs 毫秒；已 ready 立即返回 true */
    fun awaitReady(timeoutMs: Long): Boolean {
        if (ready) return true
        return ref.get().await(timeoutMs, TimeUnit.MILLISECONDS)
    }
}