package com.example.simpleproxyvpn;

/**
 * Runs the VPN tunnel read/write loop on a background thread, delegating to
 * MyVpnService. Kept as a top-level class because the dev build of d8/R8 in
 * the installed build-tools fails on nested class files.
 */
public class TunnelRunner implements Runnable {
    private final MyVpnService service;

    TunnelRunner(MyVpnService service) {
        this.service = service;
    }

    @Override
    public void run() {
        service.runTunnelLoop();
    }
}
