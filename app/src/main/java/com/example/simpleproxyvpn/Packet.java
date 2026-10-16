package com.example.simpleproxyvpn;

/**
 * Minimal IPv4/TCP parser for packets read from the VPN TUN interface, and
 * builders for the IPv4/TCP packets we write back to the TUN interface.
 */
public final class Packet {
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    public byte[] srcIp = new byte[4];
    public byte[] dstIp = new byte[4];
    public int srcPort;
    public int dstPort;
    public int protocol;
    public boolean syn;
    public boolean ack;
    public boolean fin;
    public boolean rst;
    public int seq;          // raw (unmasked)
    public int ackSeq;       // raw (unmasked)
    public int window;
    public byte[] payload;   // TCP payload (may be null)
    public int payloadLen;

    private Packet() {
    }

    public static Packet newInstance() {
        return new Packet();
    }

    /**
     * Parse an IPv4 packet whose raw bytes start at the IPv4 header.
     * Returns false if the packet is too short or not IPv4.
     */
    public static boolean parse(byte[] buf, int off, int len, Packet p) {
        if (len < 20) {
            return false;
        }
        int verIhl = buf[off] & 0xFF;
        int version = verIhl >>> 4;
        if (version != 4) {
            return false;
        }
        int ihl = (verIhl & 0x0F) * 4;
        int totalLen = ((buf[off + 2] & 0xFF) << 8) | (buf[off + 3] & 0xFF);
        if (totalLen < ihl || len < totalLen) {
            return false;
        }
        p.protocol = buf[off + 9] & 0xFF;
        System.arraycopy(buf, off + 12, p.srcIp, 0, 4);
        System.arraycopy(buf, off + 16, p.dstIp, 0, 4);

        p.syn = p.ack = p.fin = p.rst = false;
        p.payload = null;
        p.payloadLen = 0;

        if (p.protocol == PROTO_TCP && len >= ihl + 20) {
            int tcpOff = off + ihl;
            p.srcPort = ((buf[tcpOff] & 0xFF) << 8) | (buf[tcpOff + 1] & 0xFF);
            p.dstPort = ((buf[tcpOff + 2] & 0xFF) << 8) | (buf[tcpOff + 3] & 0xFF);
            p.seq = ((buf[tcpOff + 4] & 0xFF) << 24)
                    | ((buf[tcpOff + 5] & 0xFF) << 16)
                    | ((buf[tcpOff + 6] & 0xFF) << 8)
                    | (buf[tcpOff + 7] & 0xFF);
            p.ackSeq = ((buf[tcpOff + 8] & 0xFF) << 24)
                    | ((buf[tcpOff + 9] & 0xFF) << 16)
                    | ((buf[tcpOff + 10] & 0xFF) << 8)
                    | (buf[tcpOff + 11] & 0xFF);
            int dataOff = ((buf[tcpOff + 12] & 0xFF) >>> 4) * 4;
            int flags = buf[tcpOff + 13] & 0xFF;
            p.syn = (flags & 0x02) != 0;
            p.ack = (flags & 0x10) != 0;
            p.fin = (flags & 0x01) != 0;
            p.rst = (flags & 0x04) != 0;
            p.window = ((buf[tcpOff + 14] & 0xFF) << 8) | (buf[tcpOff + 15] & 0xFF);
            int tcpLen = totalLen - ihl - dataOff;
            if (tcpLen > 0) {
                p.payload = new byte[tcpLen];
                System.arraycopy(buf, tcpOff + dataOff, p.payload, 0, tcpLen);
                p.payloadLen = tcpLen;
            }
        } else if (p.protocol == PROTO_UDP && len >= ihl + 8) {
            int udpOff = off + ihl;
            p.srcPort = ((buf[udpOff] & 0xFF) << 8) | (buf[udpOff + 1] & 0xFF);
            p.dstPort = ((buf[udpOff + 2] & 0xFF) << 8) | (buf[udpOff + 3] & 0xFF);
        }
        return true;
    }

    public static String ipToString(byte[] ip) {
        return (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "." + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
    }

    public static byte[] ipv4ToBytes(String ip) {
        String[] parts = ip.split("\\.");
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            b[i] = (byte) Integer.parseInt(parts[i]);
        }
        return b;
    }

    /* ---------- checksums ---------- */

    public static short checksum(byte[] data, int off, int len) {
        long sum = 0;
        int i = off;
        int end = off + len - 1;
        while (i < end) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            i += 2;
        }
        if (i <= off + len - 1) {
            sum += (data[i] & 0xFF) << 8;
        }
        while ((sum >>> 16) != 0) {
            sum = (sum & 0xFFFFL) + (sum >>> 16);
        }
        return (short) (~sum & 0xFFFF);
    }

    /**
     * TCP checksum over the pseudo-header + TCP segment.
     * The TCP segment passed in must already have its checksum field zeroed.
     */
    public static short tcpChecksum(byte[] srcIp, byte[] dstIp,
                                    byte[] tcpSeg, int tcpSegOff, int tcpSegLen) {
        byte[] pseudo = new byte[12];
        System.arraycopy(srcIp, 0, pseudo, 0, 4);
        System.arraycopy(dstIp, 0, pseudo, 4, 4);
        pseudo[8] = 0;
        pseudo[9] = 6; // IPPROTO_TCP
        pseudo[10] = (byte) ((tcpSegLen >>> 8) & 0xFF);
        pseudo[11] = (byte) (tcpSegLen & 0xFF);

        byte[] combined = new byte[pseudo.length + tcpSegLen];
        System.arraycopy(pseudo, 0, combined, 0, pseudo.length);
        System.arraycopy(tcpSeg, tcpSegOff, combined, pseudo.length, tcpSegLen);
        return checksum(combined, 0, combined.length);
    }
}
