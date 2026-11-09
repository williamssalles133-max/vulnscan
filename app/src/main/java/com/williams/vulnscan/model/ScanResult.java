package com.williams.vulnscan.model;

import java.util.Collections;
import java.util.List;

public final class ScanResult {
    public final String label;
    public final String packageName;
    public final String versionName;
    public final long versionCode;
    public final int minSdk;
    public final int targetSdk;
    public final String apkPath;
    public final List<Finding> findings;
    public final FirebaseHints firebase;
    public final long scannedAtMillis;

    public ScanResult(
            String label,
            String packageName,
            String versionName,
            long versionCode,
            int minSdk,
            int targetSdk,
            String apkPath,
            List<Finding> findings,
            FirebaseHints firebase,
            long scannedAtMillis) {
        this.label = label;
        this.packageName = packageName;
        this.versionName = versionName;
        this.versionCode = versionCode;
        this.minSdk = minSdk;
        this.targetSdk = targetSdk;
        this.apkPath = apkPath;
        this.findings = Collections.unmodifiableList(findings);
        this.firebase = firebase;
        this.scannedAtMillis = scannedAtMillis;
    }
}
