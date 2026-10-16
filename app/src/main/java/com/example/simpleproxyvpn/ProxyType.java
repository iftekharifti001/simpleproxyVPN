package com.example.simpleproxyvpn;

/**
 * Proxy type constants (a plain class, since the dev build of d8/R8 fails on
 * enum class files produced by this javac).
 */
public final class ProxyType {
    public static final int SOCKS5 = 0;
    public static final int HTTP = 1;

    private ProxyType() {
    }
}
