package com.silentPass.vpn

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.webkit.JavascriptInterface
import com.google.gson.Gson
import java.lang.System.currentTimeMillis
import kotlin.math.max

data class CmdPayload(
    val cmd: String,
    val data: String
)

class WebAppInterface(private val context: Context, private val vpnStarter: VpnStarter) {

    // Variable to store the timestamp when the VPN was started.
    // `0L` indicates it's not running.
    @Volatile // Ensures visibility across threads
    private var vpnStartTime: Long = 0L
    private val handler = Handler(Looper.getMainLooper())
    private val MIN_UPTIME_MS = 3000L // Minimum uptime of 3 seconds

    @JavascriptInterface
    fun receiveMessageFromJS(base64Message: String) {
        try {
            val decodedBytes = Base64.decode(base64Message, Base64.DEFAULT)
            val jsonString = String(decodedBytes, Charsets.UTF_8)
            val cmdObj = Gson().fromJson(jsonString, CmdPayload::class.java)

            when (cmdObj.cmd) {
                "startVPN" -> {
                    // Record the start time
                    vpnStartTime = currentTimeMillis()
                    Log.d("WebAppInterface", "VPN start command received at $vpnStartTime")

                    val intent = Intent(context, SocketServerService::class.java).apply {
                        putExtra("VPN_DATA_B64", cmdObj.data)
                    }
                    context.startService(intent)
                    vpnStarter.onVpnStartRequested()
                }

                "openUrl" -> {
                    try {
                        val url = cmdObj.data
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                        intent.addCategory(Intent.CATEGORY_BROWSABLE)
                        context.startActivity(intent)
                    } catch (e: Exception) {
                        Log.e("WebAppInterface", "Failed to open URL: ${e.message}")
                    }
                }

                "stopVPN" -> {
                    // If VPN was never started, stop immediately.
                    if (vpnStartTime == 0L) {
                        Log.w("WebAppInterface", "Stop command received but VPN was not started. Stopping anyway.")
                        executeStop()
                        return
                    }

                    val elapsedTime = currentTimeMillis() - vpnStartTime

                    // If elapsed time is less than the minimum required uptime
                    if (elapsedTime < MIN_UPTIME_MS) {
                        val delayNeeded = MIN_UPTIME_MS - elapsedTime
                        Log.d("WebAppInterface", "Delaying stop command by $delayNeeded ms")
                        handler.postDelayed({
                            executeStop()
                        }, delayNeeded)
                    } else {
                        // If enough time has passed, stop immediately
                        Log.d("WebAppInterface", "Sufficient uptime. Stopping VPN immediately.")
                        executeStop()
                    }
                }

                else -> {
                    Log.w("WebAppInterface", "Unknown command: ${cmdObj.cmd}")
                }
            }
        } catch (e: Exception) {
            Log.e("WebAppInterface", "Error decoding Base64 or parsing JSON: $e")
        }
    }

    /**
     * Encapsulates the actual VPN stop logic to avoid code duplication.
     */
    private fun executeStop() {
        Log.d("WebAppInterface", "Executing stop logic.")
        val intent = Intent(context, SocketServerService::class.java)
        context.stopService(intent)
        vpnStarter.onVpnStopRequested()

        // Reset the start time to indicate the VPN is stopped.
        vpnStartTime = 0L
    }
}