package com.williams.vulnscan.ai;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.williams.vulnscan.analysis.ApkCodeContext;
import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.FirebaseHints;
import com.williams.vulnscan.model.ScanResult;
import com.williams.vulnscan.model.Severity;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CodeContextSummarizerTest {
    @Test
    public void masksSecretsAndStaysWithinCap() {
        String secret = "SuperSecretValue99";
        String apiKey = "AIzaSyD0123456789abcdefghijklmnopqrstuv";
        List<ApkCodeContext.Snippet> snippets = new ArrayList<>();
        snippets.add(new ApkCodeContext.Snippet(
                "assets/config.json", "string", "\"api_key\": \"" + secret + "\"", 100));
        snippets.add(new ApkCodeContext.Snippet("classes.dex", "string", apiKey, 100));
        snippets.add(new ApkCodeContext.Snippet(
                "assets/keys.pem", "string", "-----BEGIN RSA PRIVATE KEY-----\nTHISISPRIVATEKEYMATERIAL", 100));
        snippets.add(new ApkCodeContext.Snippet(
                "classes.dex", "url", "http://insecure.example/login", 85));
        for (int i = 0; i < 200; i++) {
            snippets.add(new ApkCodeContext.Snippet(
                    "classes.dex",
                    "url",
                    "https://example.com/path/" + i + "/" + "a".repeat(140),
                    60));
        }
        ApkCodeContext code = new ApkCodeContext(
                Collections.singletonList("lib/arm64-v8a/libnative.so"),
                Collections.singletonList("assets/config.json"),
                Collections.singletonList("res/xml/network_security_config.xml"),
                snippets,
                Collections.singletonList("leitura parcial"),
                1,
                8,
                20,
                2,
                true,
                true);
        Finding finding = new Finding(
                Severity.ALTO,
                "Segredo",
                "Chave \"interna\"",
                "O valor " + secret + " está no dex.",
                "classes.dex",
                secret);
        ScanResult scan = new ScanResult(
                "Meu App",
                "com.example.app",
                "1.2.0",
                4,
                24,
                34,
                "/tmp/app.apk",
                Collections.singletonList(finding),
                new FirebaseHints(null, null, null, null),
                10L);

        String json = CodeContextSummarizer.summarize(scan, null, null, code, "Meu App", "com.example.app", null);

        assertTrue(json.length() <= CodeContextSummarizer.MAX_CHARS);
        assertTrue(json.startsWith("{"));
        assertTrue(json.endsWith("}"));
        assertFalse(json.contains(secret));
        assertFalse(json.contains(apiKey));
        assertFalse(json.contains("THISISPRIVATEKEYMATERIAL"));
        assertTrue(json.contains(FindingSummarizer.mask(secret)));
        assertTrue(json.contains(FindingSummarizer.mask(apiKey)));
        assertTrue(json.contains("[chave privada mascarada]"));
        assertTrue(json.contains("lib/arm64-v8a/libnative.so"));
        assertTrue(json.contains("network_security_config.xml"));
        assertTrue(json.contains("http://insecure.example/login"));
        assertTrue(json.contains("extracaoParcial"));
        assertTrue(json.contains("Chave \\\"interna\\\""));
        assertFalse(json.contains("/tmp/app.apk"));
    }
}
