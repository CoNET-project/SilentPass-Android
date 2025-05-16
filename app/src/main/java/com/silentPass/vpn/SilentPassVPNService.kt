package com.silentPass.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import engine.Engine
import engine.Key
import java.io.FileDescriptor

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
            .addRoute("0.0.0.0", 0) // Route all traffic
            .addDisallowedApplication(this.getApplication().getPackageName())
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
        val intFd = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            vpnInterface!!.fd
        } else {
            // Android Q 以下没有 ParcelFileDescriptor.fd 字段公开，只能用反射或 native hack
            throw IllegalStateException("Android 10 以下请使用反射获取 fd")
        }
        key.setDevice("fd://$intFd")
        key.setInterface("")
        key.setLogLevel("debug");
        key.setProxy("socks5://127.0.0.1:8888") // <--- and here
        key.setRestAPI("")
        key.setTCPSendBufferSize("")
        key.setTCPReceiveBufferSize("")
        key.setTCPModerateReceiveBuffer(false)
        try {
            Engine.insert(key)
            Engine.start()
        } catch (e: Exception) {
            Log.e(TAG, "startEngine: error ${e.message}")
        }

    }


//    private fun startTun2Proxy(fd: FileDescriptor) {
//        Thread {
//            val input = FileInputStream(fd)
//            val output = FileOutputStream(fd)
//
//            // You'll need a packet forwarder here
//            val buffer = ByteArray(32767)
//            while (true) {
//                val length = input.read(buffer)
//                if (length > 0) {
//                    // Forward this data to proxy and get the response
//                    // Example: send to SOCKS5 proxy and get back response
//                    // Then write back to `output.write(response)`
//                }
//            }
//        }.start()
//    }

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
        vpnInterface?.close()
        vpnInterface = null
        engine.Engine.stop()
    }
}