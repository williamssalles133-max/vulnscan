package com.williams.vulnscan.data;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import com.williams.vulnscan.Text;

import java.io.IOException;
import java.security.GeneralSecurityException;

public final class SecurePrefs {
    private static final String FILE = "vulnscan_secure_prefs";
    private static final String KEY = "xai_api_key";
    private static final Object LOCK = new Object();

    private final SharedPreferences preferences;

    private SecurePrefs(SharedPreferences preferences) {
        this.preferences = preferences;
    }

    public static SecurePrefs open(Context context) throws GeneralSecurityException, IOException {
        synchronized (LOCK) {
            Context app = context.getApplicationContext();
            MasterKey masterKey = new MasterKey.Builder(app)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();
            SharedPreferences preferences = EncryptedSharedPreferences.create(
                    app,
                    FILE,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
            return new SecurePrefs(preferences);
        }
    }

    public String getApiKey() {
        return Text.trimToNull(preferences.getString(KEY, null));
    }

    public void setApiKey(String value) throws IOException {
        boolean ok = preferences.edit().putString(KEY, value.trim()).commit();
        if (!ok) {
            throw new IOException("commit");
        }
    }

    public void clear() throws IOException {
        boolean ok = preferences.edit().remove(KEY).commit();
        if (!ok) {
            throw new IOException("commit");
        }
    }
}
