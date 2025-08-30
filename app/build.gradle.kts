plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.google.services) // ✅ 添加 Firebase 插件（引用 toml 别名）
	id("org.jetbrains.kotlin.plugin.serialization") version "1.9.23"

}

configurations.all {

    resolutionStrategy.eachDependency {
        if (requested.group == "org.bouncycastle") {
            if (requested.name.endsWith("jdk15on")) {
                useTarget("org.bouncycastle:${requested.name.replace("jdk15on", "jdk18on")}:1.77")
                because("Force all jdk15on modules to jdk18on for compatibility")
            }
        }
    }
}

//  keytool -genkey -v -keystore SilentPassVPN.jks -keyalg RSA -keysize 2048 -validity 10000 -alias SilentPassVPN
android {
    signingConfigs {
        create("release") {
            storeFile = file("keys/my-release-key.jks")
            storePassword = "Aa123456"
            keyAlias = "myalias"
            keyPassword = "Aa123456"
        }
    }
    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    namespace = "com.silentPass.vpn"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.silentPass.vpn"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.8"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
		multiDexEnabled = true
    }

    buildTypes {
        release {

            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        compose = true
    }
    // 添加对最新 Android 插件的配置
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(files("libs/tun2socks.aar"))
    implementation("org.web3j:core:4.10.0") {
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
    }

    implementation("org.pgpainless:pgpainless-core:1.6.4") {
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
        exclude(group = "org.bouncycastle", module = "bcpg-jdk15on")
        exclude(group = "org.bouncycastle", module = "bcpkix-jdk15on")
    }
    implementation("org.nanohttpd:nanohttpd:2.3.1")
    implementation ("com.jakewharton:process-phoenix:2.1.2")
    implementation("com.github.li-xiaojun:XPopup:2.9.19")


    implementation("androidx.core:core-splashscreen:1.0.1")

    implementation ("com.google.firebase:firebase-analytics:17.4.1")
    implementation ("androidx.fragment:fragment:1.3.6") // 或者更新为最新稳定版
    // ✅ Add only the modern 18-on version
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    implementation("com.google.code.gson:gson:2.10.1")
    // The rest...
    implementation("androidx.multidex:multidex:2.0.1")

    implementation("com.google.android.material:material:1.11.0")

	    // ... 其他依赖

    // OkHttp 用于网络请求
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Kotlinx Serialization 用于 JSON 解析
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    
    // Kotlin Coroutines 协程核心库
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

	implementation ("com.squareup.okhttp3:okhttp:4.11.0")

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}