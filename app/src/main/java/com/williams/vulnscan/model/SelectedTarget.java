package com.williams.vulnscan.model;

public final class SelectedTarget {
    public enum Kind {
        INSTALLED,
        FILE
    }

    public final Kind kind;
    public final String packageName;
    public final String label;
    public final String apkPath;

    private SelectedTarget(Kind kind, String packageName, String label, String apkPath) {
        this.kind = kind;
        this.packageName = packageName;
        this.label = label;
        this.apkPath = apkPath;
    }

    public static SelectedTarget installed(String packageName, String label, String apkPath) {
        return new SelectedTarget(Kind.INSTALLED, packageName, label, apkPath);
    }

    public static SelectedTarget file(String apkPath, String label) {
        return new SelectedTarget(Kind.FILE, null, label, apkPath);
    }
}
