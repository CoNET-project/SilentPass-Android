package com.silentPass.vpn

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.WebChromeClient
import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import androidx.activity.ComponentActivity
import android.widget.Toast
import androidx.core.app.ServiceCompat.startForeground

class MainActivity : ComponentActivity() {

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            webViewClient = WebViewClient() // opens links inside WebView
            addJavascriptInterface(WebAppInterface(this@MainActivity), "AndroidBridge")
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
    }
}
