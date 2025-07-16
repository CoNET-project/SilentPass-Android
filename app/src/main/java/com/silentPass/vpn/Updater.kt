@file:OptIn(kotlinx.serialization.InternalSerializationApi::class)
package com.silentPass.vpn

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.zip.ZipInputStream


class Updater(private val context: Context) {

    private val client = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * 运行更新程序。
     * 该方法会自动从本地 'workers/update.json' 读取当前版本，
     * 然后与远程节点比较，决定是否需要下载和应用更新。
     * 成功更新后，会将新内容覆盖到 'workers' 目录。
     *
     * @param nodes 节点服务器列表，用于获取更新信息。
     * @return 如果更新成功，返回 `true`；如果无需更新或更新失败，返回 `false`。
     */
    suspend fun runUpdater(nodes: List<Node>): Boolean {
        return withContext(Dispatchers.IO) {
            Log.i("Updater", "🚀 开始执行动态节点更新程序...")
            val workersDir = File(context.filesDir, "workers")
            val tempUpdatePath = File(context.cacheDir, "conet-update-${System.currentTimeMillis()}")

            try {
                // --- 从本地文件系统获取当前版本 ---
                val localUpdateJsonFile = File(workersDir, "update.json")
                val currentVer = try {
                    if (localUpdateJsonFile.exists()) {
                        val content = localUpdateJsonFile.readText()
                        json.decodeFromString<UpdateInfo>(content).ver
                    } else {
                        Log.w("Updater", "本地 update.json 不存在，将版本视为 0.0.0")
                        "0.0.0" // 如果文件不存在，则使用一个基础版本号
                    }
                } catch (e: Exception) {
                    Log.e("Updater", "读取或解析本地 update.json 失败，将版本视为 0.0.0", e)
                    "0.0.0" // 如果解析失败，也使用基础版本号
                }
                Log.i("Updater", "✅ 检测到当前本地版本为: $currentVer")

                // --- 获取远程版本信息并比较 ---
                if (nodes.isEmpty()) throw IOException("节点列表为空")
                val selectedNode = nodes.random()
                Log.i("Updater", "✅ 节点列表获取成功！已随机选择节点: ${selectedNode.ip_addr}")
                val baseApiUrl = "http://${selectedNode.ip_addr}/silentpass-rpc/"
                val updateInfo = fetchUpdateInfo("${baseApiUrl}update.json")
                Log.i("Updater", "✅ 获取远程信息成功！最新版本: ${updateInfo.ver}")

                if (!isNewerVersion(currentVer, updateInfo.ver)) {
                    Log.i("Updater", "当前已是最新版本 ($currentVer)，无需更新。")
                    return@withContext false // 无需更新
                }

                Log.i("Updater", "发现新版本 ${updateInfo.ver}，准备更新...")

                // --- 核心下载和验证逻辑 ---
                if (tempUpdatePath.exists()) tempUpdatePath.deleteRecursively()
                tempUpdatePath.mkdirs()
                Log.i("Updater", "创建临时更新目录: ${tempUpdatePath.absolutePath}")

                val downloadUrl = "$baseApiUrl${updateInfo.filename}"
                Log.i("Updater", "⏳ 正在从 $downloadUrl 下载并解压到临时目录...")
                downloadAndUnzip(downloadUrl, tempUpdatePath)
                Log.i("Updater", "🎉 成功解压到临时目录！")

                if (!validateAndRepairContents(tempUpdatePath, nodes)) {
                    throw IOException("下载的内容无效或修复失败，已终止更新。")
                }

                // --- 新的覆盖更新逻辑 ---
                Log.i("Updater", "准备使用新内容覆盖工作目录...")
                // 1. 清空当前的工作目录
                if (workersDir.exists()) {
                    workersDir.deleteRecursively()
                }
                workersDir.mkdirs()
                // 2. 将临时目录的所有内容复制到工作目录
                tempUpdatePath.copyRecursively(workersDir, overwrite = true)
                Log.i("Updater", "✅ 更新成功！工作目录已全部替换为新版本内容。")

                true // 更新成功

            } catch (e: Exception) {
                Log.e("Updater", "❌ 更新过程中发生错误: ${e.message}", e)
                false // 更新失败
            } finally {
                if (tempUpdatePath.exists()) {
                    tempUpdatePath.deleteRecursively()
                    Log.i("Updater", "已清理临时更新目录。")
                }
            }
        }
    }

    /**
     * 验证并修复文件夹内容。
     */
    private suspend fun validateAndRepairContents(folderPath: File, nodes: List<Node>): Boolean = coroutineScope {
        Log.i("Updater", "🔍 开始验证和修复更新内容...")
        val manifestFile = File(folderPath, "asset-manifest.json")
        try {
            if (!manifestFile.exists()) {
                Log.w("Updater", "🔴 关键文件 asset-manifest.json 未找到！尝试下载...")
                val randomNode = nodes.random()
                val manifestUrl = "http://${randomNode.ip_addr}/silentpass-rpc/asset-manifest.json"
                downloadSingleFile(manifestUrl, manifestFile)
            }

            val manifest = json.decodeFromString<AssetManifest>(manifestFile.readText())
            val downloadJobs = mutableListOf<Deferred<Unit>>()

            manifest.files.values.forEach { filePath ->
                val localFilePath = filePath.removePrefix("/")
                val targetFile = File(folderPath, localFilePath)
                if (!targetFile.exists()) {
                    Log.w("Updater", "🟡 文件缺失: $localFilePath。准备下载...")
                    val randomNode = nodes.random()
                    val downloadUrl = "http://${randomNode.ip_addr}/silentpass-rpc/$localFilePath"
                    val job = async(Dispatchers.IO) {
                        downloadSingleFile(downloadUrl, targetFile)
                    }
                    downloadJobs.add(job)
                }
            }

            if (downloadJobs.isNotEmpty()) {
                Log.i("Updater", "发现 ${downloadJobs.size} 个缺失文件，开始并行下载修复...")
                downloadJobs.awaitAll()
                Log.i("Updater", "✅ 所有缺失文件已下载完成！")
            } else {
                Log.i("Updater", "✅ 所有文件均存在，无需修复。")
            }
            Log.i("Updater", "✅ 更新内容验证和修复成功！")
            true
        } catch (e: Exception) {
            Log.e("Updater", "🔴 验证或修复过程中发生严重错误:", e)
            false
        }
    }
    private fun isNewerVersion(oldVer: String, newVer: String): Boolean {
        val oldParts = oldVer.split('.').mapNotNull { it.toIntOrNull() }
        val newParts = newVer.split('.').mapNotNull { it.toIntOrNull() }
        val maxParts = maxOf(oldParts.size, newParts.size)
        for (i in 0 until maxParts) {
            val oldPart = oldParts.getOrElse(i) { 0 }
            val newPart = newParts.getOrElse(i) { 0 }
            if (newPart > oldPart) return true
            if (newPart < oldPart) return false
        }
        return false
    }


    /**
     * 下载单个文件并保存到指定路径。
     */
    private fun downloadSingleFile(url: String, destinationFile: File) {
        Log.d("Updater", "下载中: $url -> ${destinationFile.name}")
        val request = Request.Builder().url(url).build()
        val response = client.newCall(request).execute()

        if (!response.isSuccessful) {
            throw IOException("下载单个文件失败 [${response.code}]: $url")
        }

        destinationFile.parentFile?.mkdirs()
        FileOutputStream(destinationFile).use { fileOutputStream ->
            response.body!!.byteStream().use { inputStream ->
                inputStream.copyTo(fileOutputStream)
            }
        }
    }
    private suspend fun fetchUpdateInfo(url: String): UpdateInfo {
        val request = Request.Builder().url(url).build()
        val response = withContext(Dispatchers.IO) {
            client.newCall(request).execute()
        }
        if (!response.isSuccessful) throw IOException("请求失败: ${response.code}")
        val responseBody = response.body?.string() ?: throw IOException("响应体为空")
        return json.decodeFromString(responseBody)
    }
    private fun downloadAndUnzip(url: String, destDir: File) {
        val request = Request.Builder().url(url).build()
        val response = client.newCall(request).execute()
        if (!response.isSuccessful) throw IOException("下载失败: ${response.code}")

        val inputStream = response.body?.byteStream() ?: throw IOException("响应体为空")
        ZipInputStream(inputStream).use { zis ->
            var zipEntry = zis.nextEntry
            while (zipEntry != null) {
                val newFile = File(destDir, zipEntry.name)
                if (zipEntry.isDirectory) {
                    newFile.mkdirs()
                } else {
                    File(newFile.parent!!).mkdirs()
                    FileOutputStream(newFile).use { fos ->
                        zis.copyTo(fos)
                    }
                }
                zipEntry = zis.nextEntry
            }
        }
    }
}
