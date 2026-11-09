package com.williams.vulnscan.model;

public final class Finding {
    public final Severity severity;
    public final String category;
    public final String title;
    public final String detail;
    public final String location;
    /** Valor sensível completo, quando houver. A interface mostra; a IA recebe mascarado. */
    public final String sensitiveValue;

    public Finding(
            Severity severity,
            String category,
            String title,
            String detail,
            String location,
            String sensitiveValue) {
        this.severity = severity;
        this.category = category;
        this.title = title;
        this.detail = detail;
        this.location = location;
        this.sensitiveValue = sensitiveValue;
    }

    public Finding withLocation(String newLocation) {
        return new Finding(severity, category, title, detail, newLocation, sensitiveValue);
    }
}
