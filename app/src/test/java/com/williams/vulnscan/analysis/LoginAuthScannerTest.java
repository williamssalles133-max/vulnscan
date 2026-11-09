package com.williams.vulnscan.analysis;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.williams.vulnscan.model.Finding;

import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class LoginAuthScannerTest {
    @Test
    public void reportsHardcodedLoginWeaknessesWithoutTestingPasswords() throws Exception {
        String dex = "if (password.equals(\"SuperSecret1\")) {} "
                + "String h = md5(senha); "
                + "http://api.exemplo.com/v1/login "
                + "prefs.edit().putString(\"user_password\", secret) "
                + "FirebaseAuth.getInstance().signInWithEmailAndPassword "
                + "Authorization: Basic dXNlcjpwYXNz";
        List<Finding> findings = scan(dex, true, false);
        assertTrue(hasTitle(findings, "Senha comparada com valor fixo"));
        assertTrue(hasTitle(findings, "Senha conferida no próprio aparelho"));
        assertTrue(hasTitle(findings, "Senha associada a MD5 ou SHA-1"));
        assertTrue(hasTitle(findings, "Login por HTTP sem TLS"));
        assertTrue(hasTitle(findings, "Senha ou token em SharedPreferences"));
        assertTrue(hasTitle(findings, "Autenticação Basic embutida"));
        assertTrue(hasTitle(findings, "Firebase Auth no cliente"));
        assertTrue(hasTitle(findings, "Sem indício de limite de tentativas"));
        assertTrue(hasTitle(findings, "Sem network security config"));
        Finding advisory = find(findings, "Sem indício de limite de tentativas");
        assertTrue(advisory.detail.contains("não é uma conclusão"));
        assertFalse(advisory.detail.toLowerCase().contains("brute"));
    }

    @Test
    public void skipsPlainPrefsWhenEncryptedAndNotesAttemptLimit() throws Exception {
        String dex = "login() EncryptedSharedPreferences prefs.putString(\"password\", value) maxAttempts";
        List<Finding> findings = scan(dex, true, false);
        assertFalse(hasTitle(findings, "Senha ou token em SharedPreferences"));
        assertFalse(hasTitle(findings, "Sem indício de limite de tentativas"));
        assertTrue(hasTitle(findings, "Texto sugere limite de tentativas"));
    }

    private static List<Finding> scan(String dex, boolean manifestRead, boolean cleartext) throws Exception {
        File apk = File.createTempFile("login", ".apk");
        apk.deleteOnExit();
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(apk))) {
            zip.putNextEntry(new ZipEntry("classes.dex"));
            zip.write(dex.getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return new LoginAuthScanner().scan(apk, manifestRead, cleartext);
    }

    private static boolean hasTitle(List<Finding> findings, String part) {
        return find(findings, part) != null;
    }

    private static Finding find(List<Finding> findings, String part) {
        for (Finding finding : findings) {
            if (finding.title != null && finding.title.contains(part)) {
                return finding;
            }
        }
        return null;
    }
}
