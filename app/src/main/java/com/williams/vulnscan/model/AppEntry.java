package com.williams.vulnscan.model;

public final class AppEntry {
    public final String label;
    public final String packageName;
    public final boolean system;

    public AppEntry(String label, String packageName, boolean system) {
        this.label = label;
        this.packageName = packageName;
        this.system = system;
    }
}
