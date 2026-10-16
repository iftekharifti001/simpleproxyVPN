package com.example.simpleproxyvpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

/**
 * Simple VPN-over-proxy service.
 * <p>
 * Creates a TUN interface via {@link VpnService}, reads IP packets, and forwards
 * each TCP flow through a configured SOCKS5 or HTTP CONNECT proxy. DNS (UDP
 * port 53) is relayed best-effort over TCP through the same proxy so that
 * hostname resolution keeps working.
 */
public class MyVpnService extends VpnService {
    public static final String ACTION_CONNECT = "com.example.simpleproxyvpn.CONNECT";
    public static final String ACTION_DISCONNECT = "com.example.simpleproxyvpn.DISCONNECT";
    public static final String ACTION_STATUS = "com.example.simpleproxyvpn.STATUS";
    public static final String EXTRA_STATUS = "status";

    public static final String EXTRA_PROXY_TYPE = "proxyType";
    public static final String EXTRA_PROXY_HOST = "proxyHost";
    public static final String EXTRA_PROXY_PORT = "proxyPort";
    public static final String EXTRA_PROXY_USER = "proxyUser";
    public static final String EXTRA_PROXY_PASS = "proxyPass";

    private static final String CHANNEL_ID = "simpleproxyvpn_channel";
    private static final int NOTIF_ID = 1;
    private static final int MTU = 1500;
    private static final String TUN_ADDRESS = "10.0.0.2";
    private static final int TUN_PREFIX = 32;

    private volatile boolean running = false;
    private Thread tunnelThread;
    private ParcelFileDescriptor tunFd;
    private FileInputStream tunIn;
    private FileOutputStream tunOut;

    private volatile String proxyType = "SOCKS5";
    private volatile String proxyHost;
    private volatile int proxyPort = 1080;
    private volatile String proxyUser;
    private volatile String proxyPass;

    private volatile String status = "idle";

    final Map<String, Connection> connections = new HashMap<>();
    final Object connLock = new Object();

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            String action = intent.getAction();
            if (ACTION_CONNECT.equals(action)) {
                proxyType = intent.getStringExtra(EXTRA_PROXY_TYPE);
                if (proxyType == null) proxyType = "SOCKS5";
                proxyHost = intent.getStringExtra(EXTRA_PROXY_HOST);
                proxyPort = intent.getIntExtra(EXTRA_PROXY_PORT, 1080);
                proxyUser = intent.getStringExtra(EXTRA_PROXY_USER);
                proxyPass = intent.getStringExtra(EXTRA_PROXY_PASS);
                startTunnel();
            } else if (ACTION_DISCONNECT.equals(action)) {
                stopTunnel();
            }
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        stopTunnel();
    }

    /** Send a complete IPv4/TCP packet into the TUN interface. */
    void sendTunSegment(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort,
                        long seq, long ack, boolean syn, boolean ackFlag, boolean fin,
                        byte[] payload, int payloadLen) {
        if (!running || tunOut == null) {
            return;
        }
        int tcpLen = 20 + payloadLen;
        int ipLen = 20 + tcpLen;
        byte[] pkt = new byte[ipLen];

        // IPv4 header
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[1] = 0; // DSCP/ECN
        pkt[2] = (byte) ((ipLen >>> 8) & 0xFF);
        pkt[3] = (byte) (ipLen & 0xFF);
        pkt[4] = 0; // id
        pkt[5] = 0;
        pkt[6] = 0; // flags/fragment
        pkt[7] = 0;
        pkt[8] = 64; // TTL
        pkt[9] = 6; // protocol TCP
        pkt[10] = 0; // header checksum (filled below)
        pkt[11] = 0;
        System.arraycopy(srcIp, 0, pkt, 12, 4);
        System.arraycopy(dstIp, 0, pkt, 16, 4);

        int tcpOff = 20;
        pkt[tcpOff + 0] = (byte) ((srcPort >>> 8) & 0xFF);
        pkt[tcpOff + 1] = (byte) (srcPort & 0xFF);
        pkt[tcpOff + 2] = (byte) ((dstPort >>> 8) & 0xFF);
        pkt[tcpOff + 3] = (byte) (dstPort & 0xFF);
        int s = (int) (seq & 0xFFFFFFFFL);
        pkt[tcpOff + 4] = (byte) ((s >>> 24) & 0xFF);
        pkt[tcpOff + 5] = (byte) ((s >>> 16) & 0xFF);
        pkt[tcpOff + 6] = (byte) ((s >>> 8) & 0xFF);
        pkt[tcpOff + 7] = (byte) (s & 0xFF);
        int a = (int) (ack & 0xFFFFFFFFL);
        pkt[tcpOff + 8] = (byte) ((a >>> 24) & 0xFF);
        pkt[tcpOff + 9] = (byte) ((a >>> 16) & 0xFF);
        pkt[tcpOff + 10] = (byte) ((a >>> 8) & 0xFF);
        pkt[tcpOff + 11] = (byte) (a & 0xFF);
        pkt[tcpOff + 12] = (byte) ((5 << 4) & 0xFF); // data offset 5, reserved 0
        int flags = 0;
        if (syn) flags |= 0x02;
        if (ackFlag) flags |= 0x10;
        if (fin) flags |= 0x01;
        pkt[tcpOff + 13] = (byte) flags;
        pkt[tcpOff + 14] = (byte) 0xFF; // window high
        pkt[tcpOff + 15] = (byte) 0xFF; // window low
        pkt[tcpOff + 16] = 0; // checksum (filled below)
        pkt[tcpOff + 17] = 0;
        pkt[tcpOff + 18] = 0; // urgent pointer
        pkt[tcpOff + 19] = 0;
        if (payloadLen > 0 && payload != null) {
            System.arraycopy(payload, 0, pkt, tcpOff + 20, payloadLen);
        }

        short tcpCksum = Packet.tcpChecksum(srcIp, dstIp, pkt, tcpOff, tcpLen);
        pkt[tcpOff + 16] = (byte) ((tcpCksum >>> 8) & 0xFF);
        pkt[tcpOff + 17] = (byte) (tcpCksum & 0xFF);

        short ipCksum = Packet.checksum(pkt, 0, 20);
        pkt[10] = (byte) ((ipCksum >>> 8) & 0xFF);
        pkt[11] = (byte) (ipCksum & 0xFF);

        try {
            tunOut.write(pkt);
            tunOut.flush();
        } catch (java.io.IOException ignored) {
        }
    }

    void removeConnection(String key) {
        synchronized (connLock) {
            connections.remove(key);
        }
    }

    /* ---------- tunnel lifecycle ---------- */

    private void startTunnel() {
        if (running) {
            return;
        }
        ensureNotificationChannel();
        Intent notifIntent = new Intent(this, MainActivity.class);
        notifIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pi = PendingIntent.getActivity(this, 0, notifIntent,
                PendingIntent.FLAG_IMMUTABLE);
        Notification notif = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle(getString(R.string.notification_title))
                .setContentText(getString(R.string.notification_text))
                .setSmallIcon(android.R.drawable.sym_def_app_icon)
                .setContentIntent(pi)
                .build();
        startForeground(NOTIF_ID, notif);

        running = true;
        status = "connecting";
        broadcastStatus();
        tunnelThread = new Thread(new TunnelRunner(this), "vpn-tunnel-loop");
        tunnelThread.start();
    }

    private void stopTunnel() {
        running = false;
        try {
            stopForeground(true);
        } catch (Exception ignored) {
        }
        synchronized (connLock) {
            for (Connection c : connections.values()) {
                c.close();
            }
            connections.clear();
        }
        closeQuietly(tunIn);
        closeQuietly(tunOut);
        tunFd = null;
        tunIn = null;
        tunOut = null;
        status = "idle";
        broadcastStatus();
    }

    private void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
            }
        }
    }

    private void ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(CHANNEL_ID,
                    "SimpleProxyVPN", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("VPN tunnel is active");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(ch);
            }
        }
    }

    private void broadcastStatus() {
        Intent b = new Intent(ACTION_STATUS);
        b.putExtra(EXTRA_STATUS, status);
        sendBroadcast(b);
    }

    public String getStatus() {
        return status;
    }

    public void runTunnelLoop() {
        try {
            VpnService.Builder b = new Builder();
            b.setSession("SimpleProxyVPN")
                    .addAddress(TUN_ADDRESS, TUN_PREFIX)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("8.8.8.8")
                    .addDnsServer("1.1.1.1");
            tunFd = b.establish();
            if (tunFd == null) {
                running = false;
                status = "idle";
                broadcastStatus();
                try {
                    stopForeground(true);
                } catch (Exception ignored) {
                }
                return;
            }
            tunIn = new FileInputStream(tunFd.getFileDescriptor());
            tunOut = new FileOutputStream(tunFd.getFileDescriptor());

            status = "connected";
            broadcastStatus();

            byte[] buf = new byte[MTU + 4096];
            while (running) {
                int n = tunIn.read(buf);
                if (n < 0) {
                    break;
                }
                Packet p = Packet.newInstance();
                if (!Packet.parse(buf, 0, n, p)) {
                    continue;
                }
                if (p.protocol == Packet.PROTO_TCP) {
                    handleTcp(p);
                } else if (p.protocol == Packet.PROTO_UDP && p.dstPort == 53) {
                    handleDns(p);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            running = false;
            try {
                stopForeground(true);
            } catch (Exception ignored) {
            }
            status = "idle";
            broadcastStatus();
        }
    }

    /* ---------- packet handling ---------- */

    private void handleTcp(Packet p) {
        String key = Connection.keyOf(p.srcIp, p.srcPort, p.dstIp, p.dstPort);
        Connection c;
        synchronized (connLock) {
            c = connections.get(key);
        }
        if (c == null) {
            if (p.syn && !p.ack) {
                // New outbound TCP flow from a local app through the TUN.
                c = new Connection(this, key, Packet.ipToString(p.dstIp), p.dstPort,
                        p.srcIp, p.dstIp, p.srcPort);
                c.rcvNxt = p.seq + 1;
                synchronized (connLock) {
                    connections.put(key, c);
                }
                try {
                    c.establish(proxyType, proxyHost, proxyPort, proxyUser, proxyPass);
                } catch (Exception e) {
                    e.printStackTrace();
                    synchronized (connLock) {
                        connections.remove(key);
                    }
                }
            }
        } else {
            c.onSegment(p);
        }
    }

    /**
     * Best-effort DNS relay: UDP port 53 queries arriving on the TUN are
     * forwarded over TCP to 1.1.1.1:53 through the proxy, and the response is
     * written back to the TUN as a UDP packet.
     */
    private void handleDns(Packet query) {
        try {
            // Build a proxied TCP connection to 1.1.1.1:53
            String targetHost = "1.1.1.1";
            int targetPort = 53;
            int type = proxyType.equalsIgnoreCase("SOCKS5")
                    ? ProxyType.SOCKS5 : ProxyType.HTTP;
            Socket sock = ProxySocket.connect(type, proxyHost, proxyPort, proxyUser, proxyPass,
                    targetHost, targetPort);
            protect(sock);

            // DNS over TCP: 2-byte length prefix + query bytes
            byte[] qBytes = new byte[query.payloadLen];
            if (query.payload != null) {
                System.arraycopy(query.payload, 0, qBytes, 0, qBytes.length);
            }
            java.io.OutputStream out = sock.getOutputStream();
            out.write((qBytes.length >>> 8) & 0xFF);
            out.write(qBytes.length & 0xFF);
            out.write(qBytes);
            out.flush();

            java.io.InputStream in = sock.getInputStream();
            // read length prefix
            int b1 = in.read();
            int b2 = in.read();
            if (b1 < 0 || b2 < 0) {
                sock.close();
                return;
            }
            int rlen = ((b1 & 0xFF) << 8) | (b2 & 0xFF);
            byte[] response = new byte[rlen];
            int got = 0;
            while (got < rlen) {
                int r = in.read(response, got, rlen - got);
                if (r < 0) {
                    break;
                }
                got += r;
            }
            sock.close();

            if (got <= 0) {
                return;
            }

            // Send back as a UDP packet on the TUN: src=10.0.0.2:53, dst=client
            byte[] pkt = buildUdpPacket(Packet.ipv4ToBytes(TUN_ADDRESS), query.srcIp,
                    53, query.srcPort, response, got);
            try {
                if (tunOut != null) {
                    tunOut.write(pkt);
                    tunOut.flush();
                }
            } catch (java.io.IOException ignored) {
            }
        } catch (Exception e) {
            // DNS relay failure is non-fatal; DNS simply won't resolve this time.
            e.printStackTrace();
        }
    }

    private static byte[] buildUdpPacket(byte[] srcIp, byte[] dstIp,
                                         int srcPort, int dstPort,
                                         byte[] payload, int plen) {
        int udpLen = 8 + plen;
        int ipLen = 20 + udpLen;
        byte[] pkt = new byte[ipLen];
        pkt[0] = 0x45;
        pkt[1] = 0;
        pkt[2] = (byte) ((ipLen >>> 8) & 0xFF);
        pkt[3] = (byte) (ipLen & 0xFF);
        pkt[4] = 0;
        pkt[5] = 0;
        pkt[6] = 0;
        pkt[7] = 0;
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[10] = 0;
        pkt[11] = 0;
        System.arraycopy(srcIp, 0, pkt, 12, 4);
        System.arraycopy(dstIp, 0, pkt, 16, 4);

        int u = 20;
        pkt[u + 0] = (byte) ((srcPort >>> 8) & 0xFF);
        pkt[u + 1] = (byte) (srcPort & 0xFF);
        pkt[u + 2] = (byte) ((dstPort >>> 8) & 0xFF);
        pkt[u + 3] = (byte) (dstPort & 0xFF);
        pkt[u + 4] = (byte) ((udpLen >>> 8) & 0xFF);
        pkt[u + 5] = (byte) (udpLen & 0xFF);
        pkt[u + 6] = 0; // checksum (optional in IPv4)
        pkt[u + 7] = 0;
        if (plen > 0) {
            System.arraycopy(payload, 0, pkt, u + 8, plen);
        }
        short ipCksum = Packet.checksum(pkt, 0, 20);
        pkt[10] = (byte) ((ipCksum >>> 8) & 0xFF);
        pkt[11] = (byte) (ipCksum & 0xFF);
        return pkt;
    }

}
