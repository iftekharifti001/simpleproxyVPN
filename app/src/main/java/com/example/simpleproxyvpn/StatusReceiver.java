package com.example.simpleproxyvpn;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * Receives VPN status broadcasts from MyVpnService and forwards them to the UI.
 * Kept top-level so d8 does not choke on an anonymous inner class.
 */
public class StatusReceiver extends BroadcastReceiver {
    private MainActivity activity;

    StatusReceiver(MainActivity activity) {
        this.activity = activity;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }
        String status = intent.getStringExtra(MyVpnService.EXTRA_STATUS);
        if (status != null && activity != null) {
            activity.onStatusChanged(status);
        }
    }
}
