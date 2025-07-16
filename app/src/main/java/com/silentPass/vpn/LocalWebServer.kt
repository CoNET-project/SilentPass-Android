package com.silentPass.vpn

import android.content.Context
import android.util.Log
import fi.iki.elonen.NanoHTTPD
import org.json.JSONException
import org.json.JSONObject
import java.io.*
import java.text.SimpleDateFormat
import java.util.*
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

class LocalWebServer(
    private val context: Context,
    private val port: Int = 3001

) : NanoHTTPD(port) {

    // rootDir 始终指向服务器当前提供服务的目录
    private lateinit var rootDir: File
    // workersDir 是我们约定的、存放 Web 内容的唯一标准位置
    private val workersDir = File(context.filesDir, "workers")

    /**
     * 启动服务器。
     * 自动处理初始内容的解压或使用现有更新。
     */

    fun prepareAndStart() {
        try {
            // 决定使用哪个目录作为 rootDir
            prepareRootDirectory()

            // 使用准备好的 rootDir 启动 NanoHTTPD 服务
            start(SOCKET_READ_TIMEOUT, false)
            Log.i("WebServer", "✅ 本地服务器启动于 http://127.0.0.1:$port")
            Log.i("WebServer", "📁 当前服务目录: ${rootDir.absolutePath}")

        } catch (e: Exception) {
            Log.e("WebServer", "❌ 启动服务器失败: ${e.message}", e)
        }
    }

    /**
     * 准备根目录。如果 workers 目录有效，则使用它；否则从 assets 解压。
     */
    private fun prepareRootDirectory() {
        val indexFile = File(workersDir, "index.html")

        if (workersDir.exists() && indexFile.exists()) {
            // 如果 workers 目录存在且内容看起来是完整的，直接使用它
            Log.i("WebServer", "发现有效的工作目录，直接使用: ${workersDir.absolutePath}")
            this.rootDir = workersDir
        } else {
            // 否则，这是首次启动或目录已损坏，需要从 assets 解压
            Log.i("WebServer", "未找到有效的工作目录，从 assets/build3.zip 解压初始内容...")
            try {
                if (workersDir.exists()) {
                    workersDir.deleteRecursively() // 清理可能损坏的旧目录
                }
                workersDir.mkdirs() // 创建新目录

                val zipStream = context.assets.open("build3.zip")
                unzip(zipStream, workersDir)

                this.rootDir = workersDir
                Log.i("WebServer", "✅ 初始内容解压成功到: ${workersDir.absolutePath}")

            } catch (e: IOException) {
                Log.e("WebServer", "❌ 从 assets 解压初始内容失败!", e)
                throw e // 抛出异常，防止服务器在没有内容的情况下启动
            }
        }
    }

    /**
     * 公开方法，用于在运行时热更新内容目录
     * @param newRootDir 指向新的、已验证过的工作目录 (必须是 '.../files/workers')
     */
    fun updateRootDirectory(newRootDir: File) {
        if (newRootDir.absolutePath != workersDir.absolutePath) {
            Log.e("WebServer", "❌ 更新目录失败：路径必须是标准的 workers 目录")
            return
        }
        if (!newRootDir.exists() || !newRootDir.isDirectory) {
            Log.e("WebServer", "❌ 更新根目录失败：新路径无效 -> ${newRootDir.absolutePath}")
            return
        }
        Log.i("WebServer", "🔄 正在将服务目录切换到 -> ${newRootDir.absolutePath}")
        this.rootDir = newRootDir
        Log.i("WebServer", "✅ 目录切换成功！")
    }


    override fun serve(session: IHTTPSession): Response {
        val timestamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
        val method = session.method
        val uri = session.uri
        val userAgent = session.headers["user-agent"] ?: "Unknown"

        Log.i("WebServer", "🕘 $timestamp - 收到请求: $method $uri")
        Log.i("WebServer", "↪ UA: $userAgent")

        // 统一处理响应和CORS头
        val response: Response = try {
            // 新增：为 /var URI 提供专门的 GET 请求处理
            if (method == Method.GET && uri == "/ver") {
                val updateJsonFile = File(rootDir, "update.json")
                Log.i("WebServer", "↪ 解析路径: /var -> 查找 ${updateJsonFile.absolutePath}")

                if (!updateJsonFile.exists()) {
                    Log.e("WebServer", "❌ /var 请求失败: update.json 文件未找到")
                    newFixedLengthResponse(Response.Status.NOT_FOUND, "application/json", "{\"error\":\"update.json not found\"}")
                } else {
                    try {
                        val content = updateJsonFile.readText(Charsets.UTF_8)
                        val jsonObject = JSONObject(content)
                        // 安全地获取 "ver" 字段
                        val version = jsonObject.optString("ver", null)

                        if (version == null) {
                            Log.e("WebServer", "❌ /var 请求失败: update.json 中缺少 'ver' 字段")
                            newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "application/json", "{\"error\":\"'ver' key missing in update.json\"}")
                        } else {
                            // 构建只包含 "ver" 的新 JSON 对象
                            val responseJson = JSONObject()
                            responseJson.put("ver", version)
                            Log.i("WebServer", "✅ 返回版本信息: ${responseJson.toString()}")
                            newFixedLengthResponse(Response.Status.OK, "application/json", responseJson.toString())
                        }
                    } catch (e: JSONException) {
                        Log.e("WebServer", "❌ /var 请求失败: JSON 解析错误", e)
                        newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "application/json", "{\"error\":\"Invalid JSON format in update.json\"}")
                    } catch (e: IOException) {
                        Log.e("WebServer", "❌ /var 请求失败: 文件读取错误", e)
                        newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "application/json", "{\"error\":\"Could not read update.json\"}")
                    }
                }
            } else { // 保留原有的文件服务逻辑
                val path = if (uri == "/") "/index.html" else uri
                val requestedFile = File(rootDir, path).canonicalFile
                Log.i("WebServer", "↪ 解析路径：build$path")
                Log.i("WebServer", "↪ 实际文件路径：${requestedFile.absolutePath}")

                val canonicalRoot = rootDir.canonicalPath
                val canonicalRequested = requestedFile.canonicalPath

                if (requestedFile.exists() && requestedFile.isFile && canonicalRequested.startsWith(canonicalRoot)) {
                    val mime = getMimeTypeForFile(requestedFile.name)
                    Log.i("WebServer", "✅ 返回文件：${requestedFile.name} [MIME: $mime]")
                    newChunkedResponse(Response.Status.OK, mime, FileInputStream(requestedFile))
                } else {
                    Log.e("WebServer", "❌ 文件不存在或不允许访问: $canonicalRequested")
                    newFixedLengthResponse(Response.Status.NOT_FOUND, "text/plain", "404 Not Found")
                }
            }
        } catch (e: Exception) {
            Log.e("WebServer", "❌ serve 处理异常：${e.message}", e)
            newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "text/plain", "500 Internal Server Error")
        }

        // ✅ 在单一出口点为所有响应添加 CORS 头，简化代码
        response.addHeader("Access-Control-Allow-Origin", "*")
        response.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        response.addHeader("Access-Control-Allow-Headers", "Origin, Content-Type, Accept")

        return response
    }


    private fun unzip(zipInputStream: InputStream, outputDir: File) {
        ZipInputStream(BufferedInputStream(zipInputStream)).use { zis ->
            var entry: ZipEntry?
            while (zis.nextEntry.also { entry = it } != null) {
                entry?.let {
                    val file = File(outputDir, it.name)
                    if (it.isDirectory) {
                        file.mkdirs()
                    } else {
                        file.parentFile?.mkdirs()
                        FileOutputStream(file).use { fos -> zis.copyTo(fos) }
                    }
                }
            }
        }
    }
}
