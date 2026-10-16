package com.example.simpleproxyvpn;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Main screen: configure the remote SOCKS5 / HTTP CONNECT proxy and connect or
 * disconnect the VPN tunnel.
 */
public class MainActivity extends Activity implements View.OnClickListener {
    private static final int REQUEST_VPN_PERMISSION = 1001;

    private EditText hostInput;
    private EditText portInput;
    private EditText userInput;
    private EditText passInput;
    private RadioButton typeSocks5;
    private RadioButton typeHttp;
    private Button connectBtn;
    private Button disconnectBtn;
    private TextView statusText;

    private StatusReceiver statusReceiver;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        hostInput = findViewById(R.id.hostInput);
        portInput = findViewById(R.id.portInput);
        userInput = findViewById(R.id.userInput);
        passInput = findViewById(R.id.passInput);
        typeSocks5 = findViewById(R.id.typeSocks5);
        typeHttp = findViewById(R.id.typeHttp);
        connectBtn = findViewById(R.id.connectBtn);
        disconnectBtn = findViewById(R.id.disconnectBtn);
        statusText = findViewById(R.id.statusText);

        connectBtn.setOnClickListener(this);
        disconnectBtn.setOnClickListener(this);
    }

    @Override
    protected void onResume() {
        super.onResume();
        statusReceiver = new StatusReceiver(this);
        IntentFilter filter = new IntentFilter(MyVpnService.ACTION_STATUS);
        registerReceiver(statusReceiver, filter);
        setStatus("idle");
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (statusReceiver != null) {
            try {
                unregisterReceiver(statusReceiver);
            } catch (Exception ignored) {
            }
            statusReceiver = null;
        }
    }

    /** Called by StatusReceiver when the tunnel status changes. */
    void onStatusChanged(String status) {
        setStatus(status);
    }

    private void connect() {
        String host = hostInput.getText().toString().trim();
        String portText = portInput.getText().toString().trim();
        if (host.isEmpty() || portText.isEmpty()) {
            Toast.makeText(this, "Please enter proxy host and port", Toast.LENGTH_SHORT).show();
            return;
        }
        int port;
        try {
            port = Integer.parseInt(portText);
        } catch (NumberFormatException e) {
            Toast.makeText(this, "Invalid port", Toast.LENGTH_SHORT).show();
            return;
        }
        String type = typeSocks5.isChecked() ? "SOCKS5" : "HTTP";
        String user = userInput.getText().toString().trim();
        String pass = passInput.getText().toString().trim();

        // Request VPN permission if not already granted.
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            startActivityForResult(prepare, REQUEST_VPN_PERMISSION);
            return;
        }
        startVpnService(type, host, port, user, pass);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_VPN_PERMISSION) {
            if (resultCode == Activity.RESULT_OK) {
                String type = typeSocks5.isChecked() ? "SOCKS5" : "HTTP";
                String host = hostInput.getText().toString().trim();
                String portText = portInput.getText().toString().trim();
                int port = 1080;
                try {
                    port = Integer.parseInt(portText);
                } catch (NumberFormatException ignored) {
                }
                String user = userInput.getText().toString().trim();
                String pass = passInput.getText().toString().trim();
                startVpnService(type, host, port, user, pass);
            } else {
                Toast.makeText(this, R.string.msg_vpn_permission, Toast.LENGTH_LONG).show();
            }
        }
    }

    private void startVpnService(String type, String host, int port, String user, String pass) {
        Intent svc = new Intent(this, MyVpnService.class);
        svc.setAction(MyVpnService.ACTION_CONNECT);
        svc.putExtra(MyVpnService.EXTRA_PROXY_TYPE, type);
        svc.putExtra(MyVpnService.EXTRA_PROXY_HOST, host);
        svc.putExtra(MyVpnService.EXTRA_PROXY_PORT, port);
        svc.putExtra(MyVpnService.EXTRA_PROXY_USER, user);
        svc.putExtra(MyVpnService.EXTRA_PROXY_PASS, pass);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(svc);
        } else {
            startService(svc);
        }
        setStatus("connecting");
    }

    private void disconnect() {
        Intent svc = new Intent(this, MyVpnService.class);
        svc.setAction(MyVpnService.ACTION_DISCONNECT);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(svc);
        } else {
            startService(svc);
        }
        setStatus("idle");
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.connectBtn) {
            connect();
        } else if (v.getId() == R.id.disconnectBtn) {
            disconnect();
        }
    }

    void setStatus(String status) {
        int resId;
        switch (status) {
            case "connecting":
                resId = R.string.status_connecting;
                break;
            case "connected":
                resId = R.string.status_connected;
                break;
            case "disconnected":
                resId = R.string.status_disconnected;
                break;
            case "idle":
            default:
                resId = R.string.status_idle;
                break;
        }
        statusText.setText(resId);
        boolean connected = "connected".equals(status);
        connectBtn.setEnabled(!connected);
        disconnectBtn.setEnabled(connected);
    }
}
