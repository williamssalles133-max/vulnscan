package com.williams.vulnscan.analysis;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Escolhe trechos que valem contexto para um parecer defensivo.
 * Não classifica exploit nem gera instrução de ataque.
 */
public final class CodeSignals {
    public static final int PRIORITY_SECRET = 100;
    public static final int PRIORITY_CLEARTEXT = 85;
    public static final int PRIORITY_WEAK = 75;
    public static final int PRIORITY_URL = 60;
    public static final int PRIORITY_NAME = 55;
    public static final int PRIORITY_CLASS = 50;
    public static final int PRIORITY_REVIEW = 40;

    private static final Pattern URL = Pattern.compile("https?://[^\\s\"'<>\\\\]{4,180}", Pattern.CASE_INSENSITIVE);

    private CodeSignals() {
    }

    public static final class Hit {
        public final String kind;
        public final int priority;

        public Hit(String kind, int priority) {
            this.kind = kind;
            this.priority = priority;
        }

        public Hit asKind(String kind) {
            return new Hit(kind, priority);
        }
    }

    public static Hit classifyString(String text) {
        if (text == null) {
            return null;
        }
        String trimmed = text.trim();
        if (trimmed.length() < 6 || trimmed.length() > 400) {
            return null;
        }
        String lower = trimmed.toLowerCase(Locale.US);
        if (SecretText.looksSensitive(trimmed)) {
            return new Hit("string", PRIORITY_SECRET);
        }
        if (lower.contains("javascript:")) {
            return new Hit("url", PRIORITY_CLEARTEXT);
        }
        Matcher url = URL.matcher(trimmed);
        if (url.find()) {
            String found = url.group();
            int priority = found.toLowerCase(Locale.US).startsWith("http://") ? PRIORITY_CLEARTEXT : PRIORITY_URL;
            return new Hit("url", priority);
        }
        if (containsWeak(lower)) {
            return new Hit("string", PRIORITY_WEAK);
        }
        if (isSensitiveClass(trimmed)) {
            return new Hit("classe", PRIORITY_CLASS);
        }
        if (containsReview(lower)) {
            return new Hit("string", PRIORITY_REVIEW);
        }
        return null;
    }

    public static Hit classifyName(String name, boolean method) {
        if (name == null) {
            return null;
        }
        String trimmed = name.trim();
        if (trimmed.length() < 4 || trimmed.length() > 80 || !isIdentifier(trimmed)) {
            return null;
        }
        String lower = trimmed.toLowerCase(Locale.US);
        String kind = method ? "metodo" : "campo";
        if (containsAny(lower,
                "addjavascriptinterface",
                "setjavascriptenabled",
                "setallowuniversalaccessfromfileurls",
                "setallowfileaccessfromfileurls",
                "setallowfileaccess",
                "onreceivedsslerror",
                "checkservertrusted",
                "sethostnameverifier",
                "trustallcerts",
                "allowallhostname",
                "evaluatejavascript")) {
            return new Hit(kind, PRIORITY_CLEARTEXT);
        }
        if (containsAny(lower,
                "rawquery",
                "execsql",
                "loadurl",
                "setwebviewclient",
                "setsavepassword",
                "mode_world_readable",
                "mode_world_writeable",
                "getpassword",
                "setpassword",
                "isrooted",
                "checkroot",
                "detectroot",
                "isdevicerooted")) {
            return new Hit(kind, PRIORITY_NAME);
        }
        if (containsAny(lower,
                "password",
                "senha",
                "apikey",
                "api_key",
                "secretkey",
                "accesstoken",
                "privatekey",
                "clientsecret")) {
            return new Hit(kind, PRIORITY_CLASS);
        }
        return null;
    }

    /** Strings de biblioteca nativa: só URL e segredo, para não despejar ruído de libc/ssl. */
    public static Hit classifyNative(String text) {
        Hit hit = classifyString(text);
        if (hit == null) {
            return null;
        }
        if ("url".equals(hit.kind) || hit.priority >= PRIORITY_SECRET) {
            return hit.asKind("nativo");
        }
        return null;
    }

    private static boolean isSensitiveClass(String text) {
        if (text.length() < 8 || text.charAt(0) != 'L' || !text.endsWith(";")) {
            return false;
        }
        String lower = text.toLowerCase(Locale.US);
        return lower.contains("webview")
                || lower.contains("trustmanager")
                || lower.contains("hostnameverifier")
                || lower.contains("javax/crypto")
                || lower.contains("networksecurity")
                || lower.contains("sslcontext")
                || lower.contains("x509");
    }

    private static boolean containsWeak(String lower) {
        return containsAny(lower,
                "aes/ecb",
                "des/ecb",
                "rc4",
                "trustmanager",
                "hostnameverifier",
                "checkservertrusted",
                "onreceivedsslerror",
                "addjavascriptinterface",
                "setallowuniversalaccessfromfileurls",
                "setallowfileaccessfromfileurls",
                "allowallhostname",
                "x509trustmanager");
    }

    private static boolean containsReview(String lower) {
        return containsAny(lower,
                "webview",
                "setjavascriptenabled",
                "sharedpreferences",
                "mode_world_readable",
                "mode_world_writeable",
                "rawquery",
                "execsql",
                "cleartext",
                "debuggable",
                "allowbackup",
                "certificatepinner",
                "network_security_config",
                "networksecurityconfig",
                "flag_mutable",
                "pendingintent",
                "loadurl",
                "evaluatejavascript",
                "usescleartexttraffic");
    }

    private static boolean containsAny(String lower, String... needles) {
        for (String needle : needles) {
            if (lower.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isIdentifier(String name) {
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (!Character.isJavaIdentifierPart(c) && c != '$') {
                return false;
            }
        }
        return true;
    }
}
