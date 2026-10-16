# SimpleProxyVPN

A minimal Android VPN-over-proxy app. It creates a local TUN interface (via
`VpnService`) and forwards every TCP connection through a remote **SOCKS5** or
**HTTP CONNECT** proxy — similar in spirit to `tun2tap`, but much simpler and
written in plain Java (no native code).

## What it does

- Starts a system-wide VPN tunnel (all `0.0.0.0/0` traffic is routed to the app's TUN interface).
- Parses the IPv4/TCP packets arriving on the TUN interface.
- For each new TCP flow, opens a socket through the configured SOCKS5 / HTTP CONNECT proxy (the socket is "protected" so it bypasses the tunnel and does not loop back).
- Relays bytes in both directions (best-effort TCP splicing).
- Best-effort DNS: UDP port 53 queries on the tunnel are forwarded over TCP to `1.1.1.1:53` through the same proxy so hostnames can resolve.

## Project layout

```
SimpleProxyVPN/
  build.gradle                 # top-level (Android Gradle Plugin)
  settings.gradle
  app/
    build.gradle               # compileSdk 34, minSdk 21, targetSdk 34
    src/main/AndroidManifest.xml
    src/main/res/...           # layout, strings, theme
    src/main/java/com/example/simpleproxyvpn/
        MainActivity.java      # UI: proxy host/port/type/auth, connect/disconnect
        MyVpnService.java      # VpnService: tunnel setup, packet loop, status
        Connection.java        # one proxied TCP flow
        ProxySocket.java       # SOCKS5 / HTTP CONNECT client
        ProxyType.java         # proxy type constants
        Packet.java            # IPv4/TCP parser + builders + checksums
        PumpRunner.java        # proxy -> TUN pump thread
        StatusReceiver.java    # status broadcast -> UI
        TunnelRunner.java      # tunnel loop thread
```

## Building

### Option A: Android Studio / Gradle (recommended)

Open the `SimpleProxyVPN` folder in Android Studio and build `app > Build > Build Bundle(s) / APK(s) > Build APK(s)`.

Requirements: Android SDK (API 34), Android Gradle Plugin 8.2.x, Gradle 8.x, JDK 17 or 21.

> Note: this machine's JDK is 24, which the installed Gradle 8.10 / AGP 8.2 do not accept
> (class file version 68), so Gradle cannot run here. Use JDK 17/21 for the Gradle build.

### Option B: Manual SDK-tools build (no Gradle)

This is how the APK in this repo was produced, using only the Android SDK build-tools:

```sh
export ANDROID_HOME=$HOME/Library/Android/sdk   # or %LOCALAPPDATA%\Android\Sdk on Windows
export PATH=$ANDROID_HOME/build-tools/34.0.0:$PATH

# 1. Generate R.java
aapt package -f -m -J out/gen -M app/src/main/AndroidManifest.xml -S app/src/main/res -I $ANDROID_HOME/platforms/android-34/android.jar

# 2. Compile Java (source/target 8 so it works on modern javac)
javac -proc:none -source 8 -target 8 -cp "$ANDROID_HOME/platforms/android-34/android.jar;out/gen" -d out/classes \
      $(find app/src/main/java -name '*.java')

# 3. Dex
d8 --lib $ANDROID_HOME/platforms/android-34/android.jar --output out/dex out/classes

# 4. Compile resources
aapt2 compile -o out/res app/src/main/res/layout/activity_main.xml \
              app/src/main/res/values/strings.xml app/src/main/res/values/themes.xml
aapt2 link -o out/app-unsigned.apk --manifest app/src/main/AndroidManifest.xml \
           -I $ANDROID_HOME/platforms/android-34/android.jar \
           -R out/res/*.flat --auto-add-overlay

# 5. Add classes.dex into the APK (dedupe entries, since aapt2 link may duplicate some)
#    then sign:
apksigner sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android \
               --out app.apk out/app-unsigned-with-dex.apk
```

You'll need a signing keystore (`keytool -genkeypair ...`) to produce an installable APK.

## Installing

The APK requires the `BIND_VPN_SERVICE` permission, so it must be installed normally (not just signed):

```sh
adb install SimpleProxyVPN.apk
```

There is no Android device/emulator attached to this machine, so the APK has **not been
device-tested**. It compiles to a valid, verifiable signed APK, but runtime behavior
(tunnel establishment, proxy relay) should be verified on a real device or emulator.

## Using the app

1. Open **SimpleProxyVPN**.
2. Enter the remote proxy **host** and **port**, choose **SOCKS5** or **HTTP CONNECT**, and optionally enter **username / password**.
3. Tap **Connect**.
4. When the system VPN permission dialog appears, tap **Allow** (the app cannot tunnel without it).
5. Status should turn to **Connected**. All app traffic on the phone is now sent through the proxy.
6. Tap **Disconnect** to stop the tunnel.

## Caveats / limitations

- This is a **best-effort** TCP splicer, not a full TCP stack. It works for common bulk
  transfers (web, etc.) but may not handle out-of-order segments, retransmissions, or
  weird middleboxes perfectly.
- Only IPv4 TCP is tunneled. DNS is relayed best-effort over TCP to `1.1.1.1:53` via the
  proxy; if your proxy blocks port 53, hostname resolution may fail (use an HTTP proxy
  that allows it, or configure the app with an IP-based destination).
- The proxy socket is protected from the tunnel (`VpnService.protect`) so proxy traffic
  does not loop back into the TUN interface.
- minSdk 21 (Android 5.0). Foreground service is used so the tunnel survives while the
  app is in the background.

## Files of interest

- `D:\OpenCode\SimpleProxyVPN.apk` — the built, signed, installable APK (produced by the manual SDK-tools build above).
- `D:\OpenCode\SimpleProxyVPN\` — the full Android Studio-compatible project source.
