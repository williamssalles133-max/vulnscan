package com.williams.vulnscan.analysis;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.williams.vulnscan.model.Finding;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class SecretScannerTest {
    @Test
    public void findsSecretsAndFirebaseHints() throws Exception {
        String apiKey = "AIza" + "SyD0123456789abcdefghijklmnopqrstuv";
        assertEquals(39, apiKey.length());
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
                + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String dex = "prefix " + apiKey
                + " https://my-shop-default-rtdb.firebaseio.com "
                + jwt + " AKIAIOSFODNN7REALKEY suffix";
        String manifest = "-----BEGIN RSA PRIVATE KEY-----";
        String config = "{\"project_id\":\"my-shop\",\"password\":\"SuperSecret1\"}";

        File apk = File.createTempFile("vulnscan", ".apk");
        apk.deleteOnExit();
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            put(zip, "classes.dex", dex);
            put(zip, "AndroidManifest.xml", manifest);
            put(zip, "assets/config.json", config);
            put(zip, "res/drawable/logo.png", "AKIAIOSFODNN7EXAMPLE should be skipped as media");
        }

        SecretScanner.Result result = new SecretScanner().scan(apk);
        assertNotNull(result.hints);
        assertEquals(apiKey, result.hints.apiKey);
        assertEquals("my-shop", result.hints.projectId);
        assertEquals("https://my-shop-default-rtdb.firebaseio.com", result.hints.databaseUrl);

        assertTrue(containsTitle(result, "Chave de API Google"));
        assertTrue(containsTitle(result, "Chave privada"));
        assertTrue(containsTitle(result, "Chave de acesso AWS"));
        assertTrue(containsTitle(result, "JSON Web Token"));
        assertTrue(containsTitle(result, "Possível senha"));
        assertTrue(containsTitle(result, "URL de Realtime Database"));
        assertFalse(containsValue(result, "AKIAIOSFODNN7EXAMPLE"));
    }

    @Test
    public void derivesProjectFromDefaultRtdbHost() {
        assertEquals("my-shop", SecretScanner.deriveProject("https://my-shop-default-rtdb.europe-west1.firebasedatabase.app"));
        assertEquals("demo-app", SecretScanner.deriveProject("https://demo-app.firebaseio.com"));
        org.junit.Assert.assertNull(SecretScanner.deriveProject("https://example.com"));
    }

    @Test
    public void skipsNativeLibraries() {
        assertFalse(SecretScanner.shouldScan("lib/arm64-v8a/libapp.so"));
        assertTrue(SecretScanner.shouldScan("classes2.dex"));
        assertTrue(SecretScanner.shouldScan("assets/google-services.json"));
        assertFalse(SecretScanner.shouldScan("res/drawable-xxhdpi/logo.png"));
    }

    private static void put(ZipOutputStream zip, String name, String text) throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(text.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

    private static boolean containsTitle(SecretScanner.Result result, String part) {
        for (Finding finding : result.findings) {
            if (finding.title != null && finding.title.contains(part)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsValue(SecretScanner.Result result, String value) {
        for (Finding finding : result.findings) {
            if (value.equals(finding.sensitiveValue)) {
                return true;
            }
        }
        return false;
    }
}
