package com.williams.vulnscan.ai;

import com.williams.vulnscan.analysis.ApkCodeContext;
import com.williams.vulnscan.analysis.SecretText;
import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.ProbeResult;
import com.williams.vulnscan.model.ScanResult;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Monta o JSON mascarado e limitado que a análise profunda envia ao modelo.
 * Segredos passam por {@link FindingSummarizer#mask} via {@link SecretText}.
 */
public final class CodeContextSummarizer {
    static final int MAX_CHARS = 20_000;

    private CodeContextSummarizer() {
    }

    public static String summarize(
            ScanResult scan,
            List<ProbeResult> probes,
            List<Finding> extra,
            ApkCodeContext code,
            String label,
            String packageName,
            String manifestNote) {
        int[] snippetBudgets = budgets(code == null ? 0 : code.snippets.size());
        int[] findingBudgets = {24, 12, 6, 0};
        int[] nameBudgets = {80, 20, 0};
        String best = "{}";
        for (int snippets : snippetBudgets) {
            for (int findings : findingBudgets) {
                for (int names : nameBudgets) {
                    String json = render(
                            scan, probes, extra, code, label, packageName, manifestNote,
                            snippets, findings, names, 160);
                    best = json;
                    if (json.length() <= MAX_CHARS) {
                        return json;
                    }
                }
            }
        }
        if (best.length() <= MAX_CHARS) {
            return best;
        }
        return "{\"aviso\":\"Extrato grande demais para enviar. A análise ficou só com o aviso de limite.\",\"extracaoParcial\":true}";
    }

    private static int[] budgets(int available) {
        List<Integer> values = new ArrayList<>();
        int current = available;
        values.add(current);
        while (current > 0) {
            int next = current > 8 ? (current * 3) / 4 : current - 1;
            if (next >= current) {
                next = current - 1;
            }
            current = Math.max(0, next);
            values.add(current);
            if (values.size() > 8) {
                break;
            }
        }
        if (values.get(values.size() - 1) != 0) {
            values.add(0);
        }
        int[] out = new int[values.size()];
        for (int i = 0; i < values.size(); i++) {
            out[i] = values.get(i);
        }
        return out;
    }

    private static String render(
            ScanResult scan,
            List<ProbeResult> probes,
            List<Finding> extra,
            ApkCodeContext code,
            String label,
            String packageName,
            String manifestNote,
            int snippetBudget,
            int findingBudget,
            int nameBudget,
            int detailLimit) {
        boolean partial = code != null && code.truncated;
        if (code != null && (snippetBudget < code.snippets.size()
                || nameBudget < code.nativeLibraries.size()
                || nameBudget < code.assets.size()
                || nameBudget < code.resources.size())) {
            partial = true;
        }
        StringBuilder json = new StringBuilder(4096);
        json.append('{');
        field(json, "aviso", "Teste autorizado. Segredos mascarados. Diagnóstico apenas: sem exploit, injeção ou bypass.");
        json.append(',');
        json.append("\"app\":{");
        if (scan != null) {
            field(json, "nome", scan.label);
            json.append(',');
            field(json, "pacote", scan.packageName);
            json.append(',');
            field(json, "versao", scan.versionName);
            json.append(",\"minSdk\":").append(scan.minSdk);
            json.append(",\"targetSdk\":").append(scan.targetSdk);
        } else {
            field(json, "nome", label);
            json.append(',');
            field(json, "pacote", packageName == null ? "" : packageName);
        }
        json.append('}');
        appendFlags(json, scan);
        if (manifestNote != null && !manifestNote.isEmpty()) {
            json.append(',');
            field(json, "avisoManifesto", clip(SecretText.redact(manifestNote), 180));
        }
        json.append(",\"achadosDoAnalisador\":[");
        appendFindings(json, ranked(scan, extra), findingBudget, detailLimit);
        json.append(']');
        json.append(",\"sondas\":[");
        appendProbes(json, probes, Math.min(6, findingBudget == 0 ? 2 : 6));
        json.append(']');
        appendCode(json, code, snippetBudget, nameBudget, partial);
        json.append('}');
        return json.toString();
    }

    private static void appendFlags(StringBuilder json, ScanResult scan) {
        boolean debuggable = false;
        boolean backup = false;
        boolean cleartext = false;
        boolean debugCert = false;
        int exported = 0;
        if (scan != null && scan.findings != null) {
            for (Finding finding : scan.findings) {
                String title = finding.title == null ? "" : finding.title;
                if (title.contains("debuggable ativo")) {
                    debuggable = true;
                }
                if (title.contains("allowBackup ativo")) {
                    backup = true;
                }
                if (title.contains("usesCleartextTraffic ativo")) {
                    cleartext = true;
                }
                if (title.contains("certificado de debug")) {
                    debugCert = true;
                }
                if (title.contains("exportad")) {
                    exported++;
                }
            }
        }
        json.append(",\"flags\":{");
        json.append("\"debuggable\":").append(debuggable);
        json.append(",\"allowBackup\":").append(backup);
        json.append(",\"cleartext\":").append(cleartext);
        json.append(",\"certificadoDebug\":").append(debugCert);
        json.append(",\"componentesExportados\":").append(exported);
        json.append('}');
    }

    private static List<Finding> ranked(ScanResult scan, List<Finding> extra) {
        List<Finding> all = new ArrayList<>();
        if (scan != null && scan.findings != null) {
            all.addAll(scan.findings);
        }
        if (extra != null) {
            all.addAll(extra);
        }
        all.sort(Comparator.comparingInt(finding -> finding.severity.ordinal()));
        return all;
    }

    private static void appendFindings(StringBuilder json, List<Finding> findings, int budget, int detailLimit) {
        int written = 0;
        for (Finding finding : findings) {
            if (written >= budget) {
                return;
            }
            if (written > 0) {
                json.append(',');
            }
            FindingSummarizer.appendFinding(json, finding, detailLimit);
            written++;
        }
    }

    private static void appendProbes(StringBuilder json, List<ProbeResult> probes, int budget) {
        if (probes == null || budget <= 0) {
            return;
        }
        int written = 0;
        for (ProbeResult probe : probes) {
            if (written >= budget) {
                return;
            }
            if (written > 0) {
                json.append(',');
            }
            json.append('{');
            field(json, "alvo", clip(SecretText.redact(probe.target), 120));
            json.append(',');
            field(json, "status", probe.badge());
            json.append(",\"http\":").append(probe.httpCode);
            json.append(',');
            field(json, "explicacao", clip(SecretText.redact(probe.explanation), 120));
            json.append('}');
            written++;
        }
    }

    private static void appendCode(StringBuilder json, ApkCodeContext code, int snippetBudget, int nameBudget, boolean partial) {
        json.append(",\"manifestoNoApk\":").append(code != null && code.manifestPresent);
        json.append(",\"bibliotecasNativas\":[");
        if (code != null) {
            appendStrings(json, code.nativeLibraries, nameBudget);
        }
        json.append(']');
        json.append(",\"assets\":[");
        if (code != null) {
            appendStrings(json, code.assets, nameBudget);
        }
        json.append(']');
        json.append(",\"recursos\":[");
        if (code != null) {
            appendStrings(json, code.resources, nameBudget);
        }
        json.append(']');
        json.append(",\"trechos\":[");
        int written = 0;
        if (code != null) {
            for (ApkCodeContext.Snippet snippet : code.snippets) {
                if (written >= snippetBudget) {
                    break;
                }
                String text = clip(SecretText.redact(snippet.text), 160);
                if (text.isEmpty()) {
                    continue;
                }
                if (written > 0) {
                    json.append(',');
                }
                json.append('{');
                field(json, "arquivo", clip(snippet.file, 120));
                json.append(',');
                field(json, "tipo", snippet.kind);
                json.append(',');
                field(json, "texto", text);
                json.append('}');
                written++;
            }
        }
        json.append(']');
        json.append(",\"contagens\":{");
        json.append("\"dex\":").append(code == null ? 0 : code.dexFiles);
        json.append(",\"entradas\":").append(code == null ? 0 : code.entriesSeen);
        json.append(",\"stringsVistas\":").append(code == null ? 0 : code.stringsVisited);
        json.append(",\"arquivosRes\":").append(code == null ? 0 : code.resourceFiles);
        json.append(",\"trechos\":").append(written);
        json.append('}');
        json.append(",\"extracaoParcial\":").append(partial);
        json.append(",\"notas\":[");
        if (code != null) {
            appendStrings(json, code.notes, 12);
        }
        json.append(']');
    }

    private static void appendStrings(StringBuilder json, List<String> values, int limit) {
        if (values == null || limit <= 0) {
            return;
        }
        boolean first = true;
        int written = 0;
        for (String value : values) {
            if (written >= limit) {
                return;
            }
            if (!first) {
                json.append(',');
            }
            first = false;
            json.append('"').append(FindingSummarizer.escape(clip(SecretText.redact(value), 160))).append('"');
            written++;
        }
    }

    private static void field(StringBuilder json, String name, String value) {
        json.append('"').append(FindingSummarizer.escape(name)).append("\":\"")
                .append(FindingSummarizer.escape(value)).append('"');
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
