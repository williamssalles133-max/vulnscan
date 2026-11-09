package com.williams.vulnscan.ai;

import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.ProbeResult;
import com.williams.vulnscan.model.ScanResult;
import com.williams.vulnscan.model.Severity;

import java.util.ArrayList;
import java.util.List;

public final class FindingSummarizer {
    private FindingSummarizer() {
    }

    public static String summarize(ScanResult scan, List<ProbeResult> probes) {
        return summarize(scan, probes, null);
    }

    public static String summarize(ScanResult scan, List<ProbeResult> probes, List<Finding> extra) {
        String full = build(scan, probes, extra, true, 420);
        if (full.length() <= 24000) {
            return full;
        }
        return build(scan, probes, extra, false, 180);
    }

    public static String mask(String value) {
        if (value == null || value.trim().isEmpty()) {
            return "";
        }
        String trimmed = value.trim();
        if (trimmed.length() <= 12) {
            return "••••";
        }
        return trimmed.substring(0, 4) + "…" + trimmed.substring(trimmed.length() - 4);
    }

    private static String build(ScanResult scan, List<ProbeResult> probes, List<Finding> extra, boolean includeInfo, int detailLimit) {
        StringBuilder json = new StringBuilder(2048);
        json.append('{');
        if (scan == null) {
            json.append("\"app\":null");
        } else {
            json.append("\"app\":{");
            field(json, "nome", scan.label);
            json.append(',');
            field(json, "pacote", scan.packageName);
            json.append(',');
            field(json, "versao", scan.versionName);
            json.append(",\"minSdk\":").append(scan.minSdk);
            json.append(",\"targetSdk\":").append(scan.targetSdk);
            json.append('}');
        }
        json.append(",\"achados\":[");
        List<Finding> selected = new ArrayList<>();
        appendSelected(selected, scan == null ? null : scan.findings, includeInfo);
        appendSelected(selected, extra, includeInfo);
        for (int i = 0; i < selected.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            appendFinding(json, selected.get(i), detailLimit);
        }
        json.append(']');
        json.append(",\"sondas\":[");
        if (probes != null) {
            for (int i = 0; i < probes.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                ProbeResult probe = probes.get(i);
                json.append('{');
                field(json, "alvo", probe.target);
                json.append(',');
                field(json, "status", probe.badge());
                json.append(",\"http\":").append(probe.httpCode);
                json.append(',');
                field(json, "explicacao", clip(probe.explanation, detailLimit));
                json.append('}');
            }
        }
        json.append("]}");
        return json.toString();
    }

    private static void appendSelected(List<Finding> selected, List<Finding> source, boolean includeInfo) {
        if (source == null) {
            return;
        }
        for (Finding finding : source) {
            if (selected.size() >= 50) {
                return;
            }
            if (!includeInfo && finding.severity == Severity.INFO) {
                continue;
            }
            selected.add(finding);
        }
    }

    static void appendFinding(StringBuilder json, Finding finding, int detailLimit) {
        json.append('{');
        field(json, "severidade", finding.severity.label());
        json.append(',');
        field(json, "categoria", finding.category);
        json.append(',');
        field(json, "titulo", finding.title);
        json.append(',');
        String detail = finding.detail == null ? "" : finding.detail;
        if (finding.sensitiveValue != null && !finding.sensitiveValue.isEmpty()) {
            detail = detail.replace(finding.sensitiveValue, mask(finding.sensitiveValue));
            field(json, "valorMascarado", mask(finding.sensitiveValue));
            json.append(',');
        }
        field(json, "detalhe", clip(detail, detailLimit));
        json.append(',');
        field(json, "local", clip(finding.location, 180));
        json.append('}');
    }

    private static void field(StringBuilder json, String name, String value) {
        json.append('"').append(escape(name)).append("\":\"").append(escape(value)).append('"');
    }

    static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    private static String clip(String value, int limit) {
        if (value == null) {
            return "";
        }
        if (value.length() <= limit) {
            return value;
        }
        return value.substring(0, limit) + "…";
    }
}
