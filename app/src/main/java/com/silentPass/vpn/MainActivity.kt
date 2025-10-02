package com.silentPass.vpn

import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.ActivityInfo
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.PermissionRequest
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import android.widget.FrameLayout
import android.view.ViewGroup
import android.view.View
import android.view.WindowInsets
import android.graphics.Color
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.LinearLayout
import android.view.Gravity
import androidx.core.content.ContextCompat
import android.content.pm.PackageManager
import androidx.lifecycle.lifecycleScope
import com.silentPass.vpn.vpn2socks.Vpn2SocksService
import kotlinx.coroutines.launch
interface VpnStarter {
    fun onVpnStartRequested()
    fun onVpnStopRequested()
}

class MainActivity : ComponentActivity(), VpnStarter {
    private lateinit var vpnLauncher: ActivityResultLauncher<Intent>
    private lateinit var requestCameraPermissionLauncher: ActivityResultLauncher<String>
    private var pendingWebPermissionRequest: PermissionRequest? = null
    private lateinit var loadingView: FrameLayout
    private var localWebServer: LocalWebServer? = null
    private var pendingSocksConfig: SocksConfig? = null

    data class SocksConfig(
        val host: String = "127.0.0.1",
        val port: Int = 8888
    )

    companion object {
        const val VPN_REQUEST_CODE = 1000
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 启动服务器
        localWebServer = LocalWebServer(this, 3001)
        localWebServer?.prepareAndStart()
        requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_PORTRAIT

        // 注册相机权限请求
        requestCameraPermissionLauncher = registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { granted ->
            if (granted && pendingWebPermissionRequest != null) {
                pendingWebPermissionRequest?.grant(pendingWebPermissionRequest?.resources)
            } else {
                pendingWebPermissionRequest?.deny()
            }
            pendingWebPermissionRequest = null
        }

        // 创建 WebView
        val webView = WebView(this).apply {
            clipToPadding = true
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.databaseEnabled = true

            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    loadingView.visibility = View.GONE
                }
            }

            addJavascriptInterface(WebAppInterface(this@MainActivity, this@MainActivity), "AndroidBridge")
            lifecycleScope.launch {
                UpdateProcess(context = applicationContext)
            }
            webChromeClient = object : WebChromeClient() {
                override fun onConsoleMessage(consoleMessage: ConsoleMessage): Boolean {
                    Log.d(
                        "WebViewConsole",
                        "JS [${consoleMessage.messageLevel()}] @ ${consoleMessage.sourceId()}:${consoleMessage.lineNumber()} → ${consoleMessage.message()}"
                    )
                    return true
                }

                override fun onPermissionRequest(request: PermissionRequest) {
                    runOnUiThread {
                        val cameraPermission = android.Manifest.permission.CAMERA
                        if (ContextCompat.checkSelfPermission(this@MainActivity, cameraPermission)
                            == PackageManager.PERMISSION_GRANTED) {
                            request.grant(request.resources)
                        } else {
                            pendingWebPermissionRequest = request
                            requestCameraPermissionLauncher.launch(cameraPermission)
                        }
                    }
                }
            }

            loadUrl("http://localhost:3001/")
            fitsSystemWindows = true
            setOnApplyWindowInsetsListener { v: View, insets: WindowInsets ->
                val statusBarHeight = 50
                v.setPadding(0, statusBarHeight, 0, 0)
                insets
            }
        }

        WebView.setWebContentsDebuggingEnabled(true)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            allowFileAccess = true
            allowContentAccess = true
            safeBrowsingEnabled = false
        }

        // 创建 loadingView
        loadingView = FrameLayout(this@MainActivity).apply {
            setBackgroundColor(0x88000000.toInt())
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )

            val loadingLayout = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                layoutParams = FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    FrameLayout.LayoutParams.WRAP_CONTENT,
                    Gravity.CENTER
                )

                val progressBar = ProgressBar(context).apply {
                    isIndeterminate = true
                }

                val loadingText = TextView(context).apply {
                    text = "Loading..."
                    setTextColor(Color.WHITE)
                    textSize = 16f
                    setPadding(0, 16, 0, 0)
                }

                addView(progressBar)
                addView(loadingText)
            }

            addView(loadingLayout)
            visibility = View.VISIBLE
        }

        // FrameLayout 作为容器包含 WebView 和 loadingView
        val container = FrameLayout(this).apply {
            fitsSystemWindows = true
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )

            addView(webView)
            addView(loadingView)
        }

        setContentView(container)

        vpnLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == RESULT_OK) {
                startVpnService(pendingSocksConfig)
                pendingSocksConfig = null
            }
        }
    }

    override fun onVpnStartRequested() {
        // 先启动 SOCKS 服务器
        startSocksServerIfNeeded()

        // 准备 SOCKS 配置
        pendingSocksConfig = SocksConfig(
            host = "127.0.0.1",
            port = 8888
        )

        // 检查 VPN 权限
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnLauncher.launch(prepareIntent)
        } else {
            startVpnService(pendingSocksConfig)
        }
    }

    override fun onVpnStopRequested() {
        // 停止 VPN 服务
        val stopIntent = Intent(this, Vpn2SocksService::class.java).apply {
            action = Vpn2SocksService.ACTION_STOP_VPN
        }
        startService(stopIntent)

        // 同时停止 SOCKS 服务器
        stopSocksServer()
    }

    private fun startSocksServerIfNeeded() {
        val intent = Intent(this, SocketServerService::class.java)
        // Android 8.0+ 后台启动要求使用前台服务形式；服务内部已在 5s 内 startForeground
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopSocksServer() {
        val intent = Intent(this, SocketServerService::class.java)
        stopService(intent)
    }

    private fun startVpnService(config: SocksConfig?) {
        val intent = Intent(this, Vpn2SocksService::class.java).apply {
            action = Vpn2SocksService.ACTION_START_VPN
            putExtra(Vpn2SocksService.EXTRA_SOCKS_HOST, config?.host ?: "127.0.0.1")
            putExtra(Vpn2SocksService.EXTRA_SOCKS_PORT, config?.port ?: 8888)
        }
        startService(intent)
    }
}