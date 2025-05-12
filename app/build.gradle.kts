plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
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
            storeFile = file("SilentPassVPN.jks")
            storePassword = "111111"
            keyAlias = "SilentPassVPN"
            keyPassword = "111111"
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
    compileSdk = 34

    defaultConfig {
        applicationId = "com.silentPass.vpn"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

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
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        compose = true
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

    // ✅ Add only the modern 18-on version
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    implementation("com.google.code.gson:gson:2.10.1")
    // The rest...
    implementation("androidx.multidex:multidex:2.0.1")
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