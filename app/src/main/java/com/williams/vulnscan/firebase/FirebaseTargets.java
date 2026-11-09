package com.williams.vulnscan.firebase;

import com.williams.vulnscan.Text;

import java.net.URI;
import java.util.Locale;

public final class FirebaseTargets {
    private FirebaseTargets() {
    }

    public static String normalizeProjectId(String raw) {
        String value = Text.trimToNull(raw);
        if (value == null) {
            return null;
        }
        value = value.toLowerCase(Locale.US);
        if (!value.matches("[a-z][a-z0-9-]{4,28}[a-z0-9]")) {
            return null;
        }
        return value;
    }

    public static String normalizeApiKey(String raw) {
        String value = Text.trimToNull(raw);
        if (value == null || !value.matches("[A-Za-z0-9_\\-]{20,200}")) {
            return null;
        }
        return value;
    }

    /**
     * Aceita só host de Realtime Database, para a sondagem não virar um cliente HTTP genérico.
     */
    public static String normalizeDatabaseUrl(String raw) {
        String value = Text.trimToNull(raw);
        if (value == null) {
            return null;
        }
        if (value.startsWith("http://")) {
            value = "https://" + value.substring("http://".length());
        } else if (!value.startsWith("https://")) {
            value = "https://" + value;
        }
        int query = value.indexOf('?');
        if (query >= 0) {
            value = value.substring(0, query);
        }
        int hash = value.indexOf('#');
        if (hash >= 0) {
            value = value.substring(0, hash);
        }
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.endsWith("/.json")) {
            value = value.substring(0, value.length() - "/.json".length());
        } else if (value.endsWith(".json")) {
            value = value.substring(0, value.length() - ".json".length());
        }
        try {
            URI uri = URI.create(value);
            if (uri.getHost() == null) {
                return null;
            }
            String host = uri.getHost().toLowerCase(Locale.US);
            if (!(host.endsWith(".firebaseio.com") || host.endsWith(".firebasedatabase.app"))) {
                return null;
            }
            if (host.contains("..") || host.startsWith(".")) {
                return null;
            }
            return "https://" + host;
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    public static String normalizeBucket(String raw) {
        String value = Text.trimToNull(raw);
        if (value == null) {
            return null;
        }
        if (value.startsWith("gs://")) {
            value = value.substring("gs://".length());
        }
        if (value.startsWith("https://") || value.startsWith("http://")) {
            return null;
        }
        int slash = value.indexOf('/');
        if (slash >= 0) {
            value = value.substring(0, slash);
        }
        value = value.toLowerCase(Locale.US);
        if (!value.matches("[a-z0-9][a-z0-9.\\-]{2,220}[a-z0-9]")) {
            return null;
        }
        if (!(value.endsWith(".appspot.com") || value.endsWith(".firebasestorage.app"))) {
            return null;
        }
        return value;
    }
}
