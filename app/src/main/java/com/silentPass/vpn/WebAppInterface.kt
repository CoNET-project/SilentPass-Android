package com.silentPass.vpn

import android.R
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import android.webkit.JavascriptInterface
import android.widget.Toast
import com.google.gson.Gson
import android.util.Base64
import androidx.core.content.ContextCompat.startForegroundService
import com.silentPass.vpn.MainActivity.Companion.VPN_REQUEST_CODE
import engine.Engine

data class CmdPayload(
    val cmd: String,
    val data: String
)

class WebAppInterface (private val context: Context, private val vpnStarter: VpnStarter)  {
    @JavascriptInterface
    fun receiveMessageFromJS(base64Message: String) {

        try {
            val decodedBytes = Base64.decode(base64Message, Base64.DEFAULT)
            val jsonString = String(decodedBytes, Charsets.UTF_8)
            val cmdObj = Gson().fromJson(jsonString, CmdPayload::class.java)
            when (cmdObj.cmd) {
                "startVPN" -> {

                    // TODO: Trigger VPN logic here

//                    val decodedBytes = Base64.decode(cmdObj.data, Base64.DEFAULT)
//                    val jsonString = String(decodedBytes, Charsets.UTF_8)
//                    var startVPNData = Gson().fromJson(jsonString, StartVPNData::class.java)
//                    var layerMinus = LayerMinus (startVPNData)
//                    Log.d("WebAppInterface", "layerMinus exitNode size = ${layerMinus.exitNode.size}")

                    var intent = Intent(context, SocketServerService::class.java).apply {
                        putExtra("VPN_DATA_B64", cmdObj.data)
                    }
                    context.startService(intent)
                    vpnStarter.onVpnStartRequested()

//                    System.setProperty("http.proxyHost", "127.0.0.1")
//                    System.setProperty("http.proxyPort", "8888")
//                    System.setProperty("https.proxyHost", "127.0.0.1")
//                    System.setProperty("https.proxyPort", "8888")
//                    System.setProperty("socksProxyHost", "127.0.0.1")
//                    System.setProperty("socksProxyPort", "8888")

                }

                "stopVPN" -> {

                    var intent = Intent(context, SocketServerService::class.java)
                    val stopped = context.stopService(intent)
                    vpnStarter.onVpnStopRequested()
//                    // For SOCKS proxy
//                    System.clearProperty("socksProxyHost")
//                    System.clearProperty("socksProxyPort")
//
//                    // For HTTP proxy
//                    System.clearProperty("http.proxyHost")
//                    System.clearProperty("http.proxyPort")
//                    // For HTTPS proxy
//                    System.clearProperty("https.proxyHost")
//                    System.clearProperty("https.proxyPort")
//
//
//                    Log.d("WebAppInterface", "Stopping VPN")

                    // TODO: Stop VPN logic here
                }

                else -> {
                    Log.w("WebAppInterface", "Unknown command: ${cmdObj.cmd}")
                }
            }
        } catch (e: Exception) {
            Log.e("WebAppInterface", "Error decoding Base64 or parsing JSON: $e")
        }

    }
}