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
import android.view.View.OnApplyWindowInsetsListener
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.graphics.Color
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.LinearLayout
import android.view.Gravity
import androidx.core.content.ContextCompat
import android.content.pm.PackageManager
import androidx.lifecycle.lifecycleScope // 确保导入这个
import kotlinx.coroutines.delay // 确保导入这个
import kotlinx.coroutines.launch // 确保导入这个

interface VpnStarter {
    fun onVpnStartRequested()
    fun onVpnStopRequested()
}

class MainActivity : ComponentActivity(), VpnStarter {
    private lateinit var vpnLauncher: ActivityResultLauncher<Intent>
    private lateinit var permissionLauncher: ActivityResultLauncher<Array<String>>
    private lateinit var requestCameraPermissionLauncher: ActivityResultLauncher<String>
    private var pendingWebPermissionRequest: PermissionRequest? = null
    private lateinit var loadingView: FrameLayout
    private var localWebServer: LocalWebServer? = null

    private fun getStatusBarHeight(): Int {
        val resourceId = resources.getIdentifier("status_bar_height", "dimen", "android")
        return if (resourceId > 0) resources.getDimensionPixelSize(resourceId) else 0
    }

    @SuppressLint("SetJavaScriptEnabled")


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

// 启动服务器
        localWebServer = LocalWebServer(this, 3001)
        // 关键改动: Call the renamed method

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
                    loadingView.visibility = View.GONE // ✅ 页面加载完成后隐藏 loading
                }
            }

            addJavascriptInterface(WebAppInterface(this@MainActivity, this@MainActivity), "AndroidBridge")

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

//            loadUrl("https://vpn9.conet.network/")
            loadUrl("http://localhost:3001/")
//            loadUrl("http://localhost:3001/loader.html")
//            loadUrl("https://vpn4.silentpass.io/loader.html")
//              loadUrl("https://ios-test.silentpass.io/loader.html")
            fitsSystemWindows = true
            setOnApplyWindowInsetsListener { v, insets ->
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


            safeBrowsingEnabled = false // 避免拦截 localhost 资源
        }
        // 创建 loadingView（灰色背景 + 圆圈 + 文字）
        loadingView = FrameLayout(this@MainActivity).apply {
            setBackgroundColor(0x88000000.toInt()) // 半透明黑色
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
                startVpnService()
            }
        }
    }

    companion object {
        const val VPN_REQUEST_CODE = 1000
        const val ACTION_STOP_VPN = "com.silentPass.vpn.ACTION_STOP_VPN"
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
        // Create an Intent with the specific stop action
        val stopIntent = Intent(this, SilentPassVPNService::class.java).apply {
            action = SilentPassVPNService.ACTION_STOP_VPN
        }

        // Use startService to deliver the command to the running service
        startService(stopIntent)

        lifecycleScope.launch {
            try {
                // 停止服务的意图可以立即发送
                val stopIntent = Intent(this@MainActivity, SilentPassVPNService::class.java)
                stopService(stopIntent)


                // 延迟后，再调用 stopVpn()


           //     (SilentPassVPNService.instance)?.stopVpn()

            } catch (e: Exception) {
                // 记录或处理异常
                e.printStackTrace()
            }
        }

    }

    private fun startVpnService() {
        val intent = Intent(this, SilentPassVPNService::class.java)
        startService(intent)
    }
}
