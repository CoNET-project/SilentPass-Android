package com.silentPass.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import engine.Engine
import engine.Key
import java.io.FileDescriptor
import java.io.IOException

val TAG = "SilentPassVPNService"
class SilentPassVPNService: VpnService() {
    companion object {
        var instance: SilentPassVPNService? = null
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val builder = Builder()
        builder.setSession("Silent Pass VPN")
            .addAddress("10.0.0.2", 32)
            .addDnsServer("8.8.8.8")

        // 【修改点】开始: 排除本地网络
        // 注释掉原来的全流量路由规则
        // .addRoute("0.0.0.0", 0)

        // 添加新的路由规则以实现分流 (Split Tunneling)
        // 这是网络上一种常见的技巧，通过添加两个覆盖大部分公网地址的路由，
        // 来间接排除私有网络地址 (如 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)。
        // Android系统会自动处理与VPN服务器在同一子网的流量，但这种方法能更明确地排除其他私有网络。
        //
        // 注意：这个方法会把发往 127.0.0.1 (localhost) 的流量也路由到VPN。
        // 不过，因为下面调用了 addDisallowedApplication，您自己的应用（代理服务器所在的应用）
        // 访问 localhost 不会通过VPN，从而避免了死循环。但设备上其他应用访问 localhost 则会通过VPN。
        builder.addRoute("0.0.0.0", 1)
        builder.addRoute("128.0.0.0", 1)
            // 【修改点】结束

            // 将本应用排除在VPN之外，这是非常重要的一步，可以防止代理流量被自身VPN捕获导致死循环。
            .addDisallowedApplication(this.application.packageName)

        vpnInterface = builder.establish()

        vpnInterface?.let {
            startTun2Proxy(it.fileDescriptor)
        }
        Log.d(TAG, "onStartCommand called")
        return START_STICKY
    }

    private fun startTun2Proxy(fd: FileDescriptor) {
        val key = Key()
        key.setMark(0)
        key.setMTU(1500)
        // 注意：在Android 10 (Q) 以下，直接访问 .fd 会有问题。
        val intFd = vpnInterface!!.fd
        key.setDevice("fd://$intFd")
        key.setInterface("")
        key.setLogLevel("debug");
        key.setProxy("socks5://127.0.0.1:8888")
        key.setRestAPI("")
        key.setTCPSendBufferSize("")
        key.setTCPReceiveBufferSize("")
        key.setTCPModerateReceiveBuffer(false)
        try {
            Engine.insert(key)
            Engine.start()
            Log.d(TAG, "Engine started successfully.")
        } catch (e: Exception) {
            Log.e(TAG, "startEngine: error ${e.message}")
        }
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onDestroy() {
        super.onDestroy()
        instance = null
        Log.d(TAG, "onDestroy called")
    }

    fun stopVpn() {
        Log.d(TAG, "Manually stopping VPN")
        try {
            Engine.stop()
            Log.d(TAG, "Engine stopped.")
        } catch (e: Exception) {
            Log.e(TAG, "Stopping engine failed", e)
        }

        try {
            vpnInterface?.close()
            Log.d(TAG, "VPN interface closed.")
        } catch (e: IOException) {
            Log.e(TAG, "Closing vpnInterface failed", e)
        }
        vpnInterface = null
        stopSelf()
    }
}