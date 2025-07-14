package com.silentPass.vpn

import android.content.Context
import android.util.Log
import fi.iki.elonen.NanoHTTPD
import java.io.*
import java.text.SimpleDateFormat
import java.util.*
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream


class LocalWebServer(
    private val context: Context,
    private val port: Int = 3001

) : NanoHTTPD(port) {

    private lateinit var rootDir: File

    fun prepareAndStart(): Boolean {
        val version = getAppVersion(context)
        val targetDir = File(context.filesDir, "web-$version")

        val indexHtml = File(targetDir, "build/index.html")
        if (indexHtml.exists()) {
            Log.i("WebServer", "✅ 使用现有目录：${targetDir.absolutePath}")
            rootDir = targetDir
        } else {
            try {
                if (targetDir.exists()) {
                    Log.w("WebServer", "⚠️ 目录不完整，删除重解压：${targetDir.absolutePath}")
                    targetDir.deleteRecursively()
                }
                targetDir.mkdirs()

                val zipStream = context.assets.open("build3.zip")
                unzip(zipStream, targetDir)
                Log.i("WebServer", "✅ 解压成功：${targetDir.absolutePath}")
                rootDir = targetDir
            } catch (e: Exception) {
                Log.e("WebServer", "❌ 解压失败：${e.message}", e)
                return false
            }
        }

        return try {
            start(SOCKET_READ_TIMEOUT, false)
            Log.i("WebServer", "✅ 本地服务器启动：http://127.0.0.1:$port")
            true
        } catch (e: Exception) {
            Log.e("WebServer", "❌ 启动服务器失败：${e.message}", e)
            false
        }
    }

     override fun serve(session: IHTTPSession): Response {
        val timestamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
        val method = session.method
        val uri = session.uri
        val userAgent = session.headers["user-agent"] ?: "Unknown"
        val path = if (uri == "/") "/index.html" else uri

        Log.i("WebServer", "🕘 $timestamp - 收到请求: $method $uri")
        Log.i("WebServer", "↪ UA: $userAgent")

        return try {
            val requestedFile = File(rootDir, "build$path").canonicalFile
            Log.i("WebServer", "↪ 解析路径：build$path")
            Log.i("WebServer", "↪ 实际文件路径：${requestedFile.absolutePath}")

            val canonicalRoot = rootDir.canonicalPath
            val canonicalRequested = requestedFile.canonicalPath

            val response = if (requestedFile.exists() && requestedFile.isFile && canonicalRequested.startsWith(canonicalRoot)) {
                val mime = getMimeTypeForFile(requestedFile.name)
                Log.i("WebServer", "✅ 返回文件：${requestedFile.name} [MIME: $mime]")
                newChunkedResponse(Response.Status.OK, mime, FileInputStream(requestedFile))
            } else {
                Log.e("WebServer", "❌ 文件不存在或不允许访问: $canonicalRequested")
                newFixedLengthResponse(Response.Status.NOT_FOUND, "text/plain", "404 Not Found")
            }

            // ✅ 添加 CORS 头
            response.addHeader("Access-Control-Allow-Origin", "*")
            response.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            response.addHeader("Access-Control-Allow-Headers", "Origin, Content-Type, Accept")

            return response
        } catch (e: Exception) {
            Log.e("WebServer", "❌ serve 处理异常：${e.message}", e)
            val response = newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "text/plain", "500 Internal Server Error")

            // ✅ 异常返回也加上 CORS 头
            response.addHeader("Access-Control-Allow-Origin", "*")
            response.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            response.addHeader("Access-Control-Allow-Headers", "Origin, Content-Type, Accept")

            return response
        }
    }


    private fun getAppVersion(context: Context): String {
        val currentVersion = "1.1.0"
        return try {
            val pInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            return currentVersion
        } catch (e: Exception) {
            return currentVersion
        }
    }

    private fun unzip(zipInputStream: InputStream, outputDir: File) {
        ZipInputStream(BufferedInputStream(zipInputStream)).use { zis ->
            var entry: ZipEntry?
            while (zis.nextEntry.also { entry = it } != null) {
                entry?.let {
                    val file = File(outputDir, it.name)
                    if (it.isDirectory) {
                        Log.i("WebServer", "📁 创建目录：${file.absolutePath}")
                        file.mkdirs()
                    } else {
                        Log.i("WebServer", "📄 解压文件：${file.absolutePath}")
                        file.parentFile?.mkdirs()
                        FileOutputStream(file).use { fos -> zis.copyTo(fos) }
                    }
                }
            }
        }
    }
}
