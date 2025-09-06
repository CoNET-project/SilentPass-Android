package com.silentPass.vpn.vpn2socks

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.Socket

class Vpn2SocksService : VpnService() {

    companion object {

        private var vpnInterface: ParcelFileDescriptor? = null



        const val ACTION_START_VPN = "com.silentPass.vpn.ACTION_START_VPN"
        const val ACTION_STOP_VPN = "com.silentPass.vpn.ACTION_STOP_VPN"
        const val EXTRA_SOCKS_HOST = "socks_host"
        const val EXTRA_SOCKS_PORT = "socks_port"

        @Volatile private var instance: Vpn2SocksService? = null

        @Volatile private var protectionEnabled = false

        @JvmStatic
        fun protectSocket(sock: Socket): Boolean {
            // Check if VPN service instance is available
            val service = instance
            if (service == null) {
                Log.w("Vpn2SocksService", "VPN service not available")
                return false
            }

            // Try to protect the socket
            return try {
                service.protect(sock)
            } catch (e: Exception) {
                Log.e("Vpn2SocksService", "Failed to protect socket: ${e.message}")
                false
            }
        }

        // ---- Cold-start / overlay readiness gate ----
        object OverlayGate {
            private val ref = java.util.concurrent.atomic.AtomicReference(
                java.util.concurrent.CountDownLatch(1)
            )
            @Volatile private var ready = false
            fun reset() {
                ready = false
                ref.set(java.util.concurrent.CountDownLatch(1))
            }
            fun signalReady() {
                if (!ready) {
                    ready = true
                    ref.get().countDown()
                }
            }
            fun awaitReady(timeoutMs: Long): Boolean {
                if (ready) return true
                return ref.get().await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
            }
        }

        @JvmStatic
        fun protectDatagram(sock: java.net.DatagramSocket): Boolean {
            return try {
                instance?.protect(sock) ?: false
            } catch (e: Throwable) {
                Log.e("Vpn2SocksService", "protectDatagram failed: ${e.message}")
                false
            }
        }

        @JvmStatic
        fun protectFd(fd: java.io.FileDescriptor): Boolean {
            return try {
                val pfd = ParcelFileDescriptor.dup(fd)
                val ok = instance?.protect(pfd.fd) ?: false
                pfd.close()
                ok
            } catch (e: Throwable) {
                Log.e("Vpn2SocksService", "protectFd failed: ${e.message}")
                false
            }
        }
    }

    private var tunFd: ParcelFileDescriptor? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var packetIO: TunPacketIO
    private lateinit var connMgr: ConnectionManager
    private lateinit var dns: DNSInterceptor

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        scope.cancel()
        tunFd?.close()
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_VPN -> {
                val socksHost = intent.getStringExtra(EXTRA_SOCKS_HOST) ?: "127.0.0.1"
                val socksPort = intent.getIntExtra(EXTRA_SOCKS_PORT, 8888)

                Log.d("Vpn2SocksService", "Starting VPN with SOCKS: $socksHost:$socksPort")
                startTunnel(
                    fakeDns = "172.16.0.2",
                    socksHost = socksHost,
                    socksPort = socksPort
                )
                return START_STICKY
            }
            ACTION_STOP_VPN -> {
                Log.d("Vpn2SocksService", "Stopping VPN")
                stopSelf()
                return START_NOT_STICKY
            }
        }
        return START_STICKY
    }

    //      https://conet.network
    //      http://example.com
    //      https://example.com

    fun startTunnel(
        fakeDns: String = "172.16.0.2",
        socksHost: String = "127.0.0.1",
        socksPort: Int = 8888
    ) {
        if (instance == null) {
            Log.e("Vpn2SocksService", "Service instance not available!")
            return
        }

        // Reset readiness gate for this new tunnel session
        OverlayGate.reset()

        val builder = Builder()
            .setSession("SilentPass VPN")
            .addAddress("172.16.0.1", 32)
            .addDnsServer(fakeDns)
            .addRoute(fakeDns, 32)
            .addRoute("198.18.0.0", 15)
            .setMtu(1500)

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Throwable) { }

        if (android.os.Build.VERSION.SDK_INT >= 29) {
            try { builder.setMetered(false) } catch (_: Throwable) { }
        }

        tunFd = builder.establish()
        requireNotNull(tunFd) { "Failed to establish VPN" }

        // Store the VPN interface
        vpnInterface = tunFd

        // Now create DNSInterceptor (VPN is ready)
        dns = DNSInterceptor.getInstance()

        // Wait briefly for DNS to be ready
        DNSInterceptor.awaitReady(500)

        packetIO = TunPacketIO(tunFd!!)

        connMgr = ConnectionManager(
            mtu = 1500,
            fakeDns = IPv4Address.parse(fakeDns)!!,
            packetWriter = { pkts, protos -> packetIO.writePackets(pkts, protos) },
            dns = dns,
            socksEndpoint = SocksEndpoint(socksHost, socksPort)
        )

        Log.d("Vpn2SocksService", "VPN service initialized with single DNSInterceptor instance")
        // Signal that overlay/control-plane is ready for the first upstream
        OverlayGate.signalReady()
        scope.launch { packetPump() }
    }

    private suspend fun packetPump() = coroutineScope {
        val reader = packetIO.readerChannel
        while (isActive) {
            val pkt = reader.receive()
            connMgr.onPacket(pkt)
        }
    }
}