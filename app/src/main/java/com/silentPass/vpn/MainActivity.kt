package com.silentPass.vpn

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.WebChromeClient
import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import androidx.activity.ComponentActivity
import android.widget.Toast
import androidx.activity.result.ActivityResultCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.ActivityResultLauncher

interface VpnStarter {
    fun onVpnStartRequested()
    fun onVpnStopRequested()
}

class MainActivity : ComponentActivity(), VpnStarter {
    private lateinit var vpnLauncher: ActivityResultLauncher<Intent>

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            webViewClient = WebViewClient() // opens links inside WebView
            addJavascriptInterface(WebAppInterface(this@MainActivity, this@MainActivity), "AndroidBridge")
            webChromeClient = object : WebChromeClient() {
                override fun onConsoleMessage(consoleMessage: ConsoleMessage): Boolean {
                    Log.d(
                        "WebViewConsole",
                        "JS [${consoleMessage.messageLevel()}] @ ${consoleMessage.sourceId()}:${consoleMessage.lineNumber()} → ${consoleMessage.message()}"
                    )
                    return true
                }
            }
            loadUrl("https://vpn8.conet.network/") // 🔁 Replace with your URL

        }


        setContentView(webView)

        // Set up the launcher to handle VPN permission result
        vpnLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult())
            {
                result -> if (result.resultCode == RESULT_OK) {
                    startVpnService()
                }
            }
    }

    companion object {
        const val VPN_REQUEST_CODE = 1000
    }

    override fun onVpnStartRequested() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnLauncher.launch(prepareIntent)
        } else {
            startVpnService()
        }
    }

    override fun onVpnStopRequested() {
        val stopIntent = Intent(this, SilentPassVPNService::class.java)
        stopService(stopIntent)
        (SilentPassVPNService.instance)?.stopVpn()
    }

    private fun startVpnService() {
        val intent = Intent(this, SilentPassVPNService::class.java)
        startService(intent)
    }
}
