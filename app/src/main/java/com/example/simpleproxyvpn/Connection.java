package com.example.simpleproxyvpn;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Represents one proxied TCP connection. A Connection is created when the TUN
 * interface delivers the first SYN of a new TCP flow. It establishes a socket
 * through the configured SOCKS5/HTTP CONNECT proxy and relays bytes in both
 * directions, presenting a consistent (best-effort) TCP stream to the TUN side.
 */
public class Connection {
    final MyVpnService service;
    final String key;
    final String dstHost;
    final byte[] srcIp = new byte[4];   // client side (tun)
    final byte[] dstIp = new byte[4];   // server side (tun)
    final int srcPort;
    final int dstPort;

    Socket proxySocket;
    OutputStream outToProxy;
    InputStream inFromProxy;
    volatile boolean active = true;
    Thread pumpThread;

    long ourIsn;
    long sndNxt;   // next sequence number we send toward the TUN client
    long sndUna;   // oldest unacknowledged sequence number (client ACKs us)
    long rcvNxt;   // next sequence number we expect from the TUN client
    boolean synAckSent = false;

    Connection(MyVpnService service, String key, String dstHost, int dstPort,
               byte[] srcIp, byte[] dstIp, int srcPort) {
        this.service = service;
        this.key = key;
        this.dstHost = dstHost;
        this.dstPort = dstPort;
        System.arraycopy(srcIp, 0, this.srcIp, 0, 4);
        System.arraycopy(dstIp, 0, this.dstIp, 0, 4);
        this.srcPort = srcPort;
    }

    static String keyOf(byte[] sip, int sport, byte[] dip, int dport) {
        String a = Packet.ipToString(sip) + ":" + sport;
        String b = Packet.ipToString(dip) + ":" + dport;
        return a.compareTo(b) < 0 ? (a + "|" + b) : (b + "|" + a);
    }

    /**
     * Establish the proxied socket and send a SYN-ACK back toward the TUN client.
     * Caller must have already set rcvNxt based on the received SYN.
     */
    void establish(String proxyType, String proxyHost, int proxyPort,
                   String user, String pass) throws Exception {
        int type = proxyType.equalsIgnoreCase("SOCKS5")
                ? ProxyType.SOCKS5 : ProxyType.HTTP;
        proxySocket = ProxySocket.connect(type, proxyHost, proxyPort, user, pass,
                dstHost, dstPort);
        // Bypass the VPN tunnel for this socket so we do not loop back into the TUN.
        service.protect(proxySocket);
        outToProxy = proxySocket.getOutputStream();
        inFromProxy = proxySocket.getInputStream();

        ourIsn = (long) (Math.random() * 0x7FFFFFFFL) + 0x1000L;
        sndNxt = ourIsn;
        sndUna = ourIsn;

        service.sendTunSegment(srcIp, dstIp, srcPort, dstPort,
                ourIsn, rcvNxt, false, true, false, null, 0);
        synAckSent = true;

        pumpThread = new Thread(new PumpRunner(this), "proxy-to-tun-" + key);
        pumpThread.start();
    }

    /**
     * Called by the TUN reader when a TCP segment belonging to this connection arrives.
     */
    void onSegment(Packet p) {
        if (!synAckSent) {
            return; // still establishing; drop (client will retransmit)
        }
        if (p.rst) {
            active = false;
            close();
            return;
        }
        if (p.syn) {
            rcvNxt = p.seq + 1;
        }
        long nextRcv = p.seq + p.payloadLen;
        if (p.fin) {
            nextRcv += 1;
        }
        if (nextRcv > rcvNxt) {
            rcvNxt = nextRcv;
        }

        // Update send side based on client's ACK.
        if (p.ack) {
            long ackNum = p.ackSeq & 0xFFFFFFFFL;
            if (seqAfter(ackNum, sndUna)) {
                sndUna = ackNum;
            }
        }

        // ACK the client back toward the TUN.
        service.sendTunSegment(srcIp, dstIp, srcPort, dstPort,
                sndNxt, rcvNxt, false, true, false, null, 0);

        // Forward payload to the proxy.
        if (p.payloadLen > 0) {
            try {
                if (outToProxy != null) {
                    outToProxy.write(p.payload, 0, p.payloadLen);
                    outToProxy.flush();
                }
            } catch (IOException e) {
                active = false;
                close();
            }
        }

        if (p.fin) {
            active = false;
            close();
        }
    }

    void close() {
        active = false;
        try {
            if (proxySocket != null) {
                proxySocket.close();
            }
        } catch (IOException ignored) {
        }
        service.removeConnection(key);
    }

    /** Returns true if sequence a is strictly after sequence b (mod 2^32). */
    static boolean seqAfter(long a, long b) {
        return ((a - b) & 0xFFFFFFFFL) < 0x80000000L && a != b;
    }
}
