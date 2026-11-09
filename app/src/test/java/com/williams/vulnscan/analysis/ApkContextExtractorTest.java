package com.williams.vulnscan.analysis;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ApkContextExtractorTest {
    @Test
    public void readsDexTableNativeLibsAssetsAndResources() throws Exception {
        String url = "https://api.example.com/v1/login";
        String weak = "AES/ECB/PKCS5Padding";
        String type = "Landroid/webkit/WebView;";
        String method = "addJavascriptInterface";
        String field = "apiKey";
        String apiKey = "AIzaSyD0123456789abcdefghijklmnopqrstuv";
        List<String> pool = Arrays.asList(url, weak, type, method, field, apiKey, "ignored");
        byte[] dex = TinyDex.build(pool, pool.indexOf(method), pool.indexOf(field));

        File apk = File.createTempFile("vulnscan-pro", ".apk");
        apk.deleteOnExit();
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            put(zip, "classes.dex", dex);
            put(zip, "lib/arm64-v8a/libnative.so", "noise https://native.example/api noise".getBytes(StandardCharsets.US_ASCII));
            put(zip, "assets/config.json", "{\"api_key\": \"SuperSecretValue99\"}".getBytes(StandardCharsets.UTF_8));
            put(zip, "assets/keys.pem", "-----BEGIN RSA PRIVATE KEY-----\nTHISISPRIVATEKEYMATERIAL\n".getBytes(StandardCharsets.UTF_8));
            put(zip, "res/xml/network_security_config.xml", "<network-security-config/>".getBytes(StandardCharsets.UTF_8));
            put(zip, "res/drawable/logo.png", new byte[]{1, 2, 3, 4});
            put(zip, "AndroidManifest.xml", new byte[]{3, 0, 8, 0});
            put(zip, "../evil.txt", "https://should-not-extract.example".getBytes(StandardCharsets.US_ASCII));
        }

        ApkCodeContext context = new ApkContextExtractor().extract(apk);

        assertTrue(context.manifestPresent);
        assertEquals(1, context.dexFiles);
        assertTrue(context.stringsVisited > 0);
        assertTrue(context.resourceFiles >= 1);
        assertTrue(contains(context.nativeLibraries, "lib/arm64-v8a/libnative.so"));
        assertTrue(contains(context.assets, "assets/config.json"));
        assertTrue(contains(context.assets, "assets/keys.pem"));
        assertTrue(contains(context.resources, "res/xml/network_security_config.xml"));
        assertFalse(contains(context.resources, "logo.png"));
        assertTrue(hasSnippet(context, "url", url));
        assertTrue(hasSnippet(context, "string", weak));
        assertTrue(hasSnippet(context, "classe", type));
        assertTrue(hasSnippet(context, "metodo", method));
        assertTrue(hasSnippet(context, "campo", field));
        assertTrue(hasSnippet(context, "string", apiKey));
        assertTrue(hasSnippet(context, "nativo", "https://native.example/api"));
        assertTrue(hasText(context, "SuperSecretValue99"));
        assertTrue(hasText(context, "BEGIN RSA PRIVATE KEY"));
        assertFalse(hasText(context, "https://should-not-extract.example"));
        assertTrue(joined(context.notes).contains(".."));
        assertNotNull(context.snippets);
    }

    @Test
    public void fallsBackToReadableStringsWhenDexHeaderIsMissing() throws Exception {
        File apk = File.createTempFile("vulnscan-pro-raw", ".apk");
        apk.deleteOnExit();
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            put(zip, "classes2.dex", "prefix http://insecure.example/login suffix".getBytes(StandardCharsets.US_ASCII));
        }
        ApkCodeContext context = new ApkContextExtractor().extract(apk);
        assertEquals(1, context.dexFiles);
        assertTrue(hasSnippet(context, "url", "http://insecure.example/login"));
        assertTrue(context.truncated || joined(context.notes).contains("DEX"));
    }

    @Test
    public void capsSnippets() throws Exception {
        File apk = File.createTempFile("vulnscan-pro-cap", ".apk");
        apk.deleteOnExit();
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 30; i++) {
            body.append("https://example.com/item/").append(i).append("/login\n");
        }
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            put(zip, "classes.dex", body.toString().getBytes(StandardCharsets.US_ASCII));
        }
        ApkContextExtractor.Limits limits = new ApkContextExtractor.Limits(
                1024 * 1024, 1024, 1024, 3, 5, 100, 8);
        ApkCodeContext context = new ApkContextExtractor().extract(java.util.Collections.singletonList(apk), limits);
        assertTrue(context.snippets.size() <= 3);
        assertTrue(context.truncated);
    }

    private static void put(ZipOutputStream zip, String name, byte[] data) throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(data);
        zip.closeEntry();
    }

    private static boolean contains(List<String> values, String part) {
        for (String value : values) {
            if (value.contains(part)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasSnippet(ApkCodeContext context, String kind, String text) {
        for (ApkCodeContext.Snippet snippet : context.snippets) {
            if (kind.equals(snippet.kind) && snippet.text.contains(text)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasText(ApkCodeContext context, String text) {
        for (ApkCodeContext.Snippet snippet : context.snippets) {
            if (snippet.text.contains(text)) {
                return true;
            }
        }
        return false;
    }

    private static String joined(List<String> notes) {
        StringBuilder builder = new StringBuilder();
        for (String note : notes) {
            builder.append(note).append('\n');
        }
        return builder.toString();
    }
}
