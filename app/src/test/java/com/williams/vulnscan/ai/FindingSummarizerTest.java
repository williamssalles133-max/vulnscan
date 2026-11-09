package com.williams.vulnscan.ai;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.FirebaseHints;
import com.williams.vulnscan.model.ProbeResult;
import com.williams.vulnscan.model.ScanResult;
import com.williams.vulnscan.model.Severity;

import org.junit.Test;

import java.util.Collections;

public class FindingSummarizerTest {
    @Test
    public void masksSecretsAndEscapesJson() throws Exception {
        String secret = "SuperSecretValue99";
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
                "1.2",
                3,
                24,
                34,
                "/tmp/app.apk",
                Collections.singletonList(finding),
                new FirebaseHints(null, null, null, null),
                10L);
        ProbeResult probe = new ProbeResult(
                "Cloud Firestore (leitura)",
                ProbeResult.Status.ABERTO,
                200,
                "HTTP 200. leitura aberta");
        String json = FindingSummarizer.summarize(scan, Collections.singletonList(probe));

        assertFalse(json.contains(secret));
        assertTrue(json.contains(FindingSummarizer.mask(secret)));
        assertTrue(json.contains("Chave \\\"interna\\\""));
        assertTrue(json.contains("ABERTO (vulnerável)"));
        assertTrue(json.contains("com.example.app"));
    }
}
