package com.silentPass.vpn

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen

class SplashActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        // Android 12+ 的系统启动图支持
        installSplashScreen()

        super.onCreate(savedInstanceState)

        // 跳转到主界面
        val intent = Intent(this, MainActivity::class.java)
        startActivity(intent)
        finish()
    }
}