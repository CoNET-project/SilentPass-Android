@file:OptIn(kotlinx.serialization.InternalSerializationApi::class)
package com.silentPass.vpn
// 关键改动: 将 OptIn 注解移到文件顶部，并添加 @file:

// AssetManifest.kt
import kotlinx.serialization.Serializable
// 现在这个注解对下面的所有 data class 都有效
@Serializable
data class AssetManifest(
    val files: Map<String, String>,
    val entrypoints: List<String>
)

@Serializable
data class UpdateInfo(
    val ver: String,
    val filename: String
)


data class Node (
    val country: String,
    val ip_addr: String,
    val region: String,
    val armoredPublicKey: String,
    val nftNumber: String
)

data class StartVPNData(
    val entryNodes: List<Node>,
    val exitNode: List<Node>,
    val privateKey: String
)

data class VE_IPptpStream (
    val host: String,
    val port: String,
    val buffer: String,
    val uuid: String
)

data class SICommandObj (
    val command: String,
    val algorithm: String,
    val Securitykey: String,
    val requestData: List<VE_IPptpStream>,
    val walletAddress: String
)

data class requestData (
    val message: String,
    val signMessage: String
)

data class postHttp (
    val data: String
)

data class CmdPayload(
    val cmd: String,
    val data: String
)