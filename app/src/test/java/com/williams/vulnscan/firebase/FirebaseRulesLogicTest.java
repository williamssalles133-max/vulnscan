package com.williams.vulnscan.firebase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.williams.vulnscan.model.ProbeResult;

import org.junit.Test;

public class FirebaseRulesLogicTest {
    @Test
    public void normalizesOnlyFirebaseDatabases() {
        assertEquals(
                "https://my-shop-default-rtdb.firebaseio.com",
                FirebaseTargets.normalizeDatabaseUrl("http://my-shop-default-rtdb.firebaseio.com/.json"));
        assertEquals(
                "https://my-shop.europe-west1.firebasedatabase.app",
                FirebaseTargets.normalizeDatabaseUrl("my-shop.europe-west1.firebasedatabase.app/"));
        assertNull(FirebaseTargets.normalizeDatabaseUrl("https://example.com/.json"));
        assertNull(FirebaseTargets.normalizeDatabaseUrl("https://evil.firebaseio.com.attacker.test"));
    }

    @Test
    public void validatesProjectAndBucket() {
        assertEquals("my-shop", FirebaseTargets.normalizeProjectId("My-Shop"));
        assertNull(FirebaseTargets.normalizeProjectId("ab"));
        assertNull(FirebaseTargets.normalizeProjectId("bad id"));
        assertEquals("my-shop.appspot.com", FirebaseTargets.normalizeBucket("gs://my-shop.appspot.com/folder"));
        assertNull(FirebaseTargets.normalizeBucket("not-a-bucket"));
    }

    @Test
    public void classifiesFirestoreRead() {
        ProbeResult open = FirebaseResponseClassifier.firestoreRead(200, "{\"documents\":[]}");
        assertEquals(ProbeResult.Status.ABERTO, open.status);
        assertTrue(open.explanation.contains("200"));

        ProbeResult closed = FirebaseResponseClassifier.firestoreRead(
                403,
                "{\"error\":{\"status\":\"PERMISSION_DENIED\",\"message\":\"Missing or insufficient permissions.\"}}");
        assertEquals(ProbeResult.Status.PROTEGIDO, closed.status);

        ProbeResult disabled = FirebaseResponseClassifier.firestoreRead(
                403,
                "{\"error\":{\"status\":\"PERMISSION_DENIED\",\"message\":\"Cloud Firestore API has not been used in project before or it is disabled.\"}}");
        assertEquals(ProbeResult.Status.INCONCLUSIVO, disabled.status);

        ProbeResult badKey = FirebaseResponseClassifier.firestoreRead(
                400,
                "{\"error\":{\"message\":\"API key not valid. Please pass a valid API key.\"}}");
        assertEquals(ProbeResult.Status.ERRO, badKey.status);
    }

    @Test
    public void classifiesRealtimeAndStorage() {
        ProbeResult open = FirebaseResponseClassifier.realtime(200, "null");
        assertEquals(ProbeResult.Status.ABERTO, open.status);
        assertTrue(open.explanation.contains("null"));

        ProbeResult closed = FirebaseResponseClassifier.realtime(401, "{\"error\":\"Permission denied\"}");
        assertEquals(ProbeResult.Status.PROTEGIDO, closed.status);

        ProbeResult missing = FirebaseResponseClassifier.realtime(404, "{\"error\":\"404 Not Found\"}");
        assertEquals(ProbeResult.Status.INCONCLUSIVO, missing.status);

        ProbeResult storage = FirebaseResponseClassifier.storage("Cloud Storage", 200, "{\"items\":[]}");
        assertEquals(ProbeResult.Status.ABERTO, storage.status);
        assertTrue(!storage.explanation.contains("items"));
    }
}
