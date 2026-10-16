package com.example.simpleproxyvpn;

import java.io.IOException;

/**
 * Pumps bytes received from the proxy socket back into the TUN interface as
 * IPv4/TCP segments. Runs on its own thread per proxied connection.
 */
public class PumpRunner implements Runnable {
    private final Connection c;

    PumpRunner(Connection c) {
        this.c = c;
    }

    @Override
    public void run() {
        byte[] buf = new byte[16384];
        try {
            while (c.active) {
                int n = c.inFromProxy.read(buf);
                if (n < 0) {
                    break;
                }
                c.service.sendTunSegment(c.srcIp, c.dstIp, c.srcPort, c.dstPort,
                        c.sndNxt, c.rcvNxt, false, true, false, buf, n);
                c.sndNxt += n;
            }
        } catch (IOException e) {
            // expected on close
        }
        c.active = false;
        c.close();
    }
}
