package com.example.simpleproxyvpn;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Connects to a remote SOCKS5 or HTTP CONNECT proxy and returns a Socket that is
 * already connected through the proxy to the target host:port.
 */
public final class ProxySocket {
    private static final int CONNECT_TIMEOUT_MS = 10000;

    private ProxySocket() {
    }

    /**
     * Open a socket through the proxy to targetHost:targetPort.
     * The returned Socket is connected through the proxy; the remote target sees
     * the connection as coming from the proxy.
     */
    public static Socket connect(int type, String proxyHost, int proxyPort,
                                 String user, String pass,
                                 String targetHost, int targetPort) throws IOException {
        Socket sock = new Socket();
        sock.connect(new InetSocketAddress(proxyHost, proxyPort), CONNECT_TIMEOUT_MS);
        sock.setTcpNoDelay(true);
        OutputStream out = sock.getOutputStream();
        InputStream in = sock.getInputStream();

        if (type == ProxyType.SOCKS5) {
            socks5Connect(out, in, user, pass, targetHost, targetPort);
        } else {
            httpConnect(out, in, user, pass, targetHost, targetPort);
        }
        return sock;
    }

    /* ---------- SOCKS5 ---------- */

    private static void socks5Connect(OutputStream out, InputStream in,
                                      String user, String pass,
                                      String host, int port) throws IOException {
        boolean hasAuth = (user != null && !user.isEmpty());

        // Greeting: VERSION=5, NMETHODS, METHODS...
        byte[] greeting = new byte[hasAuth ? 4 : 3];
        greeting[0] = 0x05;
        greeting[1] = hasAuth ? (byte) 2 : (byte) 1;
        greeting[2] = 0x00; // NO AUTHENTICATION REQUIRED
        if (hasAuth) {
            greeting[3] = 0x02; // USERNAME/PASSWORD
        }
        out.write(greeting);
        out.flush();

        int ver = readByte(in);
        int method = readByte(in);
        if (ver != 0x05) {
            throw new IOException("Bad SOCKS5 greeting reply (ver=" + ver + ")");
        }
        if (method == (byte) 0xFF) {
            throw new IOException("No acceptable SOCKS5 authentication method");
        }

        if (hasAuth) {
            if (method != 0x02) {
                throw new IOException("SOCKS5 server did not select user/pass auth");
            }
            // Username/password auth (RFC 1929)
            byte[] ub = user.getBytes(StandardCharsets.UTF_8);
            byte[] pb = pass.getBytes(StandardCharsets.UTF_8);
            out.write(0x01); // subnegotiation version
            out.write(ub.length);
            out.write(ub, 0, ub.length);
            out.write(pb.length);
            out.write(pb, 0, pb.length);
            out.flush();
            int r1 = readByte(in);
            int r2 = readByte(in);
            if (r1 != 0x01 || r2 != 0x00) {
                throw new IOException("SOCKS5 authentication failed (r1=" + r1 + " r2=" + r2 + ")");
            }
        }

        // CONNECT request
        byte[] addr = encodeAddress(host);
        byte atyp = addr[0];
        byte[] req = new byte[4 + addr.length + 2];
        req[0] = 0x05; // VERSION
        req[1] = 0x01; // CMD CONNECT
        req[2] = 0x00; // RSV
        req[3] = atyp; // ATYP
        System.arraycopy(addr, 0, req, 4, addr.length);
        req[4 + addr.length] = (byte) ((port >>> 8) & 0xFF);
        req[5 + addr.length] = (byte) (port & 0xFF);
        out.write(req);
        out.flush();

        // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
        if (readByte(in) != 0x05) {
            throw new IOException("Bad SOCKS5 connect reply version");
        }
        int rep = readByte(in);
        if (rep != 0x00) {
            throw new IOException("SOCKS5 connect failed, rep=" + rep);
        }
        readByte(in); // RSV
        int atyp2 = readByte(in);
        if (atyp2 == 0x01) {
            skip(in, 4); // IPv4
        } else if (atyp2 == 0x03) {
            int len = readByte(in);
            skip(in, len); // domain
        } else if (atyp2 == 0x04) {
            skip(in, 16); // IPv6
        } else {
            throw new IOException("Unknown SOCKS5 reply atyp=" + atyp2);
        }
        skip(in, 2); // port
    }

    private static byte[] encodeAddress(String host) {
        if (isIpv4(host)) {
            byte[] ip = ipv4ToBytes(host);
            byte[] b = new byte[5];
            b[0] = 0x01; // ATYP IPv4
            System.arraycopy(ip, 0, b, 1, 4);
            return b;
        }
        byte[] hb = host.getBytes(StandardCharsets.UTF_8);
        byte[] b = new byte[1 + hb.length];
        b[0] = (byte) hb.length; // ATYP domain
        System.arraycopy(hb, 0, b, 1, hb.length);
        return b;
    }

    /* ---------- HTTP CONNECT ---------- */

    private static void httpConnect(OutputStream out, InputStream in,
                                    String user, String pass,
                                    String host, int port) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("CONNECT ").append(host).append(':').append(port).append(" HTTP/1.1\r\n");
        sb.append("Host: ").append(host).append("\r\n");
        sb.append("Proxy-Connection: Keep-Alive\r\n");
        if (user != null && !user.isEmpty()) {
            String creds = user + ':' + (pass == null ? "" : pass);
            String token = Base64.getEncoder().encodeToString(creds.getBytes(StandardCharsets.ISO_8859_1));
            sb.append("Proxy-Authorization: Basic ").append(token).append("\r\n");
        }
        sb.append("\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.US_ASCII));
        out.flush();

        // Read response headers until the blank line.
        StringBuilder resp = new StringBuilder();
        int consecutiveNewlines = 0;
        while (true) {
            int ch = readByte(in);
            if (ch < 0) {
                throw new IOException("Connection closed while reading HTTP CONNECT response");
            }
            resp.append((char) ch);
            if (ch == '\n') {
                consecutiveNewlines++;
                if (consecutiveNewlines >= 2) {
                    break;
                }
            } else if (ch != '\r') {
                consecutiveNewlines = 0;
            }
        }
        String r = resp.toString();
        if (!r.contains(" 200 ")) {
            throw new IOException("HTTP CONNECT failed: " + r.trim().replace("\r\n", " | "));
        }
    }

    /* ---------- helpers ---------- */

    private static int readByte(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) {
            throw new IOException("Unexpected end of stream");
        }
        return b;
    }

    private static void skip(InputStream in, int n) throws IOException {
        while (n > 0) {
            long skipped = in.skip(n);
            if (skipped <= 0) {
                // skip() may return 0; fall back to reading byte-by-byte
                if (in.read() < 0) {
                    throw new IOException("Unexpected end of stream while skipping");
                }
                n--;
            } else {
                n -= (int) skipped;
            }
        }
    }

    private static boolean isIpv4(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty()) {
                return false;
            }
            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
            }
            int val;
            try {
                val = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return false;
            }
            if (val < 0 || val > 255) {
                return false;
            }
        }
        return true;
    }

    private static byte[] ipv4ToBytes(String ip) {
        String[] parts = ip.split("\\.");
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            b[i] = (byte) Integer.parseInt(parts[i]);
        }
        return b;
    }
}
