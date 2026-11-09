package com.williams.vulnscan.analysis;

import com.williams.vulnscan.ai.FindingSummarizer;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reconhece segredos no texto extraído e os mascara com {@link FindingSummarizer#mask}.
 * O valor completo não entra no JSON enviado à IA.
 */
public final class SecretText {
    private static final Pattern GOOGLE_API = Pattern.compile("AIza[0-9A-Za-z_\\-]{35}");
    private static final Pattern AWS = Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b");
    private static final Pattern JWT = Pattern.compile(
            "eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}");
    private static final Pattern STRIPE = Pattern.compile("\\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\\b");
    private static final Pattern GITHUB = Pattern.compile(
            "\\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\\b");
    private static final Pattern SLACK = Pattern.compile("\\bxox[baprs]-[A-Za-z0-9\\-]{10,}");
    private static final Pattern BEARER = Pattern.compile("(?i)\\bBearer\\s+[A-Za-z0-9\\-._~+/]{12,}=*");
    private static final Pattern BASIC = Pattern.compile("(?i)\\bBasic\\s+[A-Za-z0-9+/]{12,}={0,2}");
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)\\b(password|senha|passwd|api[_\\-]?key|secret|access[_\\-]?token|client[_\\-]?secret|auth[_\\-]?token)\\b"
                    + "[\\s\"'`:={]{0,16}[\"']?([A-Za-z0-9_\\-./+=]{6,120})");

    private SecretText() {
    }

    public static boolean looksSensitive(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        if (isPrivateKey(value)) {
            return true;
        }
        return GOOGLE_API.matcher(value).find()
                || AWS.matcher(value).find()
                || JWT.matcher(value).find()
                || STRIPE.matcher(value).find()
                || GITHUB.matcher(value).find()
                || SLACK.matcher(value).find()
                || BEARER.matcher(value).find()
                || BASIC.matcher(value).find()
                || ASSIGNMENT.matcher(value).find();
    }

    public static String redact(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        if (isPrivateKey(value)) {
            return "[chave privada mascarada]";
        }
        String out = maskMatches(value, GOOGLE_API);
        out = maskMatches(out, AWS);
        out = maskMatches(out, JWT);
        out = maskMatches(out, STRIPE);
        out = maskMatches(out, GITHUB);
        out = maskMatches(out, SLACK);
        out = maskMatches(out, BEARER);
        out = maskMatches(out, BASIC);
        return maskAssignments(out);
    }

    private static boolean isPrivateKey(String value) {
        String lower = value.toLowerCase(Locale.US);
        return lower.contains("private key")
                || lower.contains("begin rsa")
                || lower.contains("begin openssh")
                || lower.contains("begin ec")
                || lower.contains("begin dsa");
    }

    private static String maskMatches(String text, Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        StringBuffer buffer = new StringBuffer();
        while (matcher.find()) {
            matcher.appendReplacement(buffer, Matcher.quoteReplacement(FindingSummarizer.mask(matcher.group())));
        }
        matcher.appendTail(buffer);
        return buffer.toString();
    }

    private static String maskAssignments(String text) {
        Matcher matcher = ASSIGNMENT.matcher(text);
        StringBuffer buffer = new StringBuffer();
        while (matcher.find()) {
            String prefix = matcher.group().substring(0, matcher.start(2) - matcher.start());
            String masked = FindingSummarizer.mask(matcher.group(2));
            matcher.appendReplacement(buffer, Matcher.quoteReplacement(prefix + masked));
        }
        matcher.appendTail(buffer);
        return buffer.toString();
    }
}
