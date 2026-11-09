package com.williams.vulnscan.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

/**
 * Extrai contexto de código de um APK (zip) só em memória: manifesto presente,
 * strings de classes*.dex, nomes de bibliotecas .so, assets e recursos.
 * Não grava arquivo, não altera o pacote e não instrumenta outro processo.
 */
public final class ApkContextExtractor {
    public static final class Limits {
        public final int maxDexBytes;
        public final int maxStreamBytes;
        public final int maxTextAssetBytes;
        public final int maxSnippets;
        public final int maxNames;
        public final int maxEntries;
        public final int maxNotes;

        public Limits(
                int maxDexBytes,
                int maxStreamBytes,
                int maxTextAssetBytes,
                int maxSnippets,
                int maxNames,
                int maxEntries,
                int maxNotes) {
            this.maxDexBytes = maxDexBytes;
            this.maxStreamBytes = maxStreamBytes;
            this.maxTextAssetBytes = maxTextAssetBytes;
            this.maxSnippets = maxSnippets;
            this.maxNames = maxNames;
            this.maxEntries = maxEntries;
            this.maxNotes = maxNotes;
        }

        public static Limits standard() {
            return new Limits(
                    16 * 1024 * 1024,
                    1024 * 1024,
                    128 * 1024,
                    140,
                    80,
                    4_000,
                    12);
        }
    }

    public ApkCodeContext extract(java.io.File apk) throws IOException {
        return extract(java.util.Collections.singletonList(apk), Limits.standard());
    }

    public ApkCodeContext extract(List<java.io.File> apks) throws IOException {
        return extract(apks, Limits.standard());
    }

    public ApkCodeContext extract(List<java.io.File> apks, Limits limits) throws IOException {
        Bucket bucket = new Bucket(limits == null ? Limits.standard() : limits);
        if (apks == null || apks.isEmpty()) {
            return bucket.build();
        }
        ZipException failure = null;
        boolean opened = false;
        for (java.io.File apk : apks) {
            if (apk == null || !apk.isFile()) {
                continue;
            }
            try (ZipFile zip = new ZipFile(apk)) {
                opened = true;
                walk(zip, bucket);
            } catch (ZipException ex) {
                failure = ex;
                bucket.note("Não foi possível abrir " + apk.getName() + " como APK.");
            }
        }
        if (!opened && failure != null) {
            throw failure;
        }
        return bucket.build();
    }

    private static void walk(ZipFile zip, Bucket bucket) {
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            if (bucket.entriesSeen >= bucket.limits.maxEntries) {
                bucket.truncated = true;
                bucket.note("Lista de entradas cortada no limite.");
                return;
            }
            ZipEntry entry = entries.nextElement();
            bucket.entriesSeen++;
            String name = entry.getName();
            if (name == null || name.isEmpty() || entry.isDirectory()) {
                continue;
            }
            if (name.contains("..")) {
                bucket.truncated = true;
                bucket.note("Entrada com '..' foi ignorada e nada foi gravado em disco.");
                continue;
            }
            String lower = name.toLowerCase(Locale.US);
            if (lower.equals("androidmanifest.xml") || lower.endsWith("/androidmanifest.xml")) {
                bucket.manifestPresent = true;
                continue;
            }
            if (isDex(lower)) {
                readDex(zip, entry, name, bucket);
                continue;
            }
            if (lower.endsWith(".so")) {
                bucket.addName(bucket.nativeLibraries, name, "bibliotecas nativas");
                scanStream(zip, entry, name, bucket, bucket.limits.maxStreamBytes, true);
                continue;
            }
            if (isAsset(lower)) {
                bucket.addName(bucket.assets, name, "assets");
                if (isText(lower)) {
                    scanStream(zip, entry, name, bucket, bucket.limits.maxTextAssetBytes, false);
                }
                continue;
            }
            if (isResource(lower)) {
                bucket.resourceFiles++;
                if (isInterestingResource(lower)) {
                    bucket.addName(bucket.resources, name, "recursos");
                    if (isText(lower)) {
                        scanStream(zip, entry, name, bucket, bucket.limits.maxTextAssetBytes, false);
                    }
                }
            }
        }
    }

    private static void readDex(ZipFile zip, ZipEntry entry, String name, Bucket bucket) {
        boolean[] truncated = {false};
        byte[] data;
        try (InputStream in = zip.getInputStream(entry)) {
            data = readAtMost(in, bucket.limits.maxDexBytes, truncated);
        } catch (IOException ex) {
            bucket.note("Falha ao ler " + clip(name, 80) + ".");
            return;
        }
        if (entry.getSize() > bucket.limits.maxDexBytes || truncated[0]) {
            bucket.truncated = true;
            bucket.note(clip(name, 80) + " foi lido só até o limite de tamanho.");
        }
        bucket.dexFiles++;
        if (DexStringTable.looksLikeDex(data)) {
            DexStringTable.read(data, new DexStringTable.Sink() {
                @Override
                public void string(String text) {
                    bucket.stringsVisited++;
                    accept(name, text, false, bucket);
                }

                @Override
                public void method(String method) {
                    CodeSignals.Hit hit = CodeSignals.classifyName(method, true);
                    if (hit != null) {
                        bucket.addSnippet(name, hit.kind, method, hit.priority);
                    }
                }

                @Override
                public void field(String field) {
                    CodeSignals.Hit hit = CodeSignals.classifyName(field, false);
                    if (hit != null) {
                        bucket.addSnippet(name, hit.kind, field, hit.priority);
                    }
                }
            });
            return;
        }
        bucket.note(clip(name, 80) + " não é um DEX reconhecido; foram usadas strings legíveis.");
        collectAscii(data, name, bucket, false);
    }

    private static void scanStream(ZipFile zip, ZipEntry entry, String name, Bucket bucket, int cap, boolean nativeLib) {
        if (cap <= 0) {
            return;
        }
        boolean[] truncated = {false};
        try (InputStream in = zip.getInputStream(entry)) {
            scanPrintable(in, cap, name, bucket, nativeLib, truncated);
        } catch (IOException ex) {
            bucket.note("Falha ao ler " + clip(name, 80) + ".");
            return;
        }
        if (truncated[0] || entry.getSize() > cap) {
            bucket.truncated = true;
        }
    }

    private static void scanPrintable(
            InputStream in,
            int cap,
            String file,
            Bucket bucket,
            boolean nativeLib,
            boolean[] truncated) throws IOException {
        byte[] buffer = new byte[8192];
        StringBuilder current = new StringBuilder();
        int total = 0;
        int read;
        while ((read = in.read(buffer)) >= 0) {
            for (int i = 0; i < read; i++) {
                if (total >= cap) {
                    truncated[0] = true;
                    emitRun(current, file, bucket, nativeLib);
                    return;
                }
                total++;
                int value = buffer[i] & 0xff;
                if (value >= 32 && value < 127) {
                    if (current.length() < 400) {
                        current.append((char) value);
                    } else {
                        emitRun(current, file, bucket, nativeLib);
                        current.setLength(0);
                        current.append((char) value);
                    }
                } else {
                    emitRun(current, file, bucket, nativeLib);
                    current.setLength(0);
                }
            }
        }
        emitRun(current, file, bucket, nativeLib);
    }

    private static void emitRun(StringBuilder current, String file, Bucket bucket, boolean nativeLib) {
        if (current.length() < 6) {
            return;
        }
        bucket.stringsVisited++;
        accept(file, current.toString(), nativeLib, bucket);
    }

    private static void collectAscii(byte[] data, String file, Bucket bucket, boolean nativeLib) {
        int start = -1;
        for (int i = 0; i <= data.length; i++) {
            boolean printable = i < data.length && data[i] >= 32 && data[i] < 127;
            if (printable) {
                if (start < 0) {
                    start = i;
                }
            } else if (start >= 0) {
                int from = start;
                while (from < i) {
                    int end = Math.min(i, from + 240);
                    if (end - from >= 6) {
                        bucket.stringsVisited++;
                        accept(file, new String(data, from, end - from, StandardCharsets.ISO_8859_1), nativeLib, bucket);
                    }
                    if (end == i) {
                        break;
                    }
                    from += 160;
                }
                start = -1;
            }
        }
    }

    private static void accept(String file, String text, boolean nativeLib, Bucket bucket) {
        CodeSignals.Hit hit = nativeLib ? CodeSignals.classifyNative(text) : CodeSignals.classifyString(text);
        if (hit != null) {
            bucket.addSnippet(file, hit.kind, text, hit.priority);
        }
    }

    private static byte[] readAtMost(InputStream in, int cap, boolean[] truncated) throws IOException {
        byte[] buffer = new byte[16384];
        byte[] data = new byte[Math.min(Math.max(cap, 0), 64 * 1024)];
        int total = 0;
        int read;
        while ((read = in.read(buffer)) >= 0) {
            if (read == 0) {
                continue;
            }
            if (total >= cap) {
                truncated[0] = true;
                break;
            }
            int allowed = Math.min(read, cap - total);
            if (total + allowed > data.length) {
                byte[] grown = new byte[Math.min(cap, Math.max(data.length * 2, total + allowed))];
                System.arraycopy(data, 0, grown, 0, total);
                data = grown;
            }
            System.arraycopy(buffer, 0, data, total, allowed);
            total += allowed;
            if (allowed < read) {
                truncated[0] = true;
                break;
            }
        }
        if (total == data.length) {
            return data;
        }
        byte[] exact = new byte[total];
        System.arraycopy(data, 0, exact, 0, total);
        return exact;
    }

    static boolean isDex(String lower) {
        int slash = lower.lastIndexOf('/');
        String base = slash >= 0 ? lower.substring(slash + 1) : lower;
        if (!base.endsWith(".dex") || !base.startsWith("classes")) {
            return false;
        }
        String middle = base.substring("classes".length(), base.length() - ".dex".length());
        if (middle.isEmpty()) {
            return true;
        }
        for (int i = 0; i < middle.length(); i++) {
            if (!Character.isDigit(middle.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isAsset(String lower) {
        return lower.startsWith("assets/") || lower.contains("/assets/");
    }

    private static boolean isResource(String lower) {
        return lower.startsWith("res/") || lower.contains("/res/");
    }

    private static boolean isInterestingResource(String lower) {
        if (lower.startsWith("meta-inf/") || lower.startsWith("kotlin/")) {
            return false;
        }
        return lower.contains("/xml/")
                || lower.contains("/raw/")
                || lower.contains("network")
                || lower.contains("security")
                || lower.contains("backup")
                || lower.contains("filepath")
                || lower.contains("file_path");
    }

    private static boolean isText(String lower) {
        return lower.endsWith(".json")
                || lower.endsWith(".xml")
                || lower.endsWith(".txt")
                || lower.endsWith(".properties")
                || lower.endsWith(".js")
                || lower.endsWith(".html")
                || lower.endsWith(".htm")
                || lower.endsWith(".conf")
                || lower.endsWith(".cfg")
                || lower.endsWith(".yml")
                || lower.endsWith(".yaml")
                || lower.endsWith(".pem")
                || lower.endsWith(".web");
    }

    private static String clip(String value, int limit) {
        if (value == null || value.length() <= limit) {
            return value == null ? "" : value;
        }
        return value.substring(0, limit) + "…";
    }

    private static final class Bucket {
        final Limits limits;
        final List<String> nativeLibraries = new ArrayList<>();
        final List<String> assets = new ArrayList<>();
        final List<String> resources = new ArrayList<>();
        final List<ApkCodeContext.Snippet> snippets = new ArrayList<>();
        final List<String> notes = new ArrayList<>();
        final Set<String> seen = new LinkedHashSet<>();
        final Set<String> noted = new LinkedHashSet<>();
        int dexFiles;
        int entriesSeen;
        int stringsVisited;
        int resourceFiles;
        boolean manifestPresent;
        boolean truncated;
        boolean cappedNatives;
        boolean cappedAssets;
        boolean cappedResources;

        Bucket(Limits limits) {
            this.limits = limits;
        }

        void addName(List<String> dest, String name, String label) {
            if (dest.size() >= limits.maxNames) {
                truncated = true;
                if (dest == nativeLibraries && !cappedNatives) {
                    cappedNatives = true;
                    note("Lista de " + label + " cortada.");
                } else if (dest == assets && !cappedAssets) {
                    cappedAssets = true;
                    note("Lista de " + label + " cortada.");
                } else if (dest == resources && !cappedResources) {
                    cappedResources = true;
                    note("Lista de " + label + " cortada.");
                }
                return;
            }
            dest.add(name.length() > 160 ? name.substring(0, 160) : name);
        }

        void addSnippet(String file, String kind, String text, int priority) {
            if (text == null || text.isEmpty() || kind == null) {
                return;
            }
            String clipped = text.length() > 240 ? text.substring(0, 240) : text;
            if (!seen.add(kind + "\0" + clipped)) {
                return;
            }
            if (snippets.size() >= limits.maxSnippets && priority <= lowestPriority()) {
                truncated = true;
                return;
            }
            snippets.add(new ApkCodeContext.Snippet(file, kind, clipped, priority));
            if (snippets.size() > limits.maxSnippets) {
                dropLowest();
                truncated = true;
            }
        }

        void note(String message) {
            if (message == null || message.isEmpty() || !noted.add(message)) {
                return;
            }
            if (notes.size() >= limits.maxNotes) {
                truncated = true;
                return;
            }
            notes.add(message);
        }

        int lowestPriority() {
            int lowest = Integer.MAX_VALUE;
            for (ApkCodeContext.Snippet snippet : snippets) {
                if (snippet.priority < lowest) {
                    lowest = snippet.priority;
                }
            }
            return lowest == Integer.MAX_VALUE ? 0 : lowest;
        }

        void dropLowest() {
            int index = 0;
            for (int i = 1; i < snippets.size(); i++) {
                if (snippets.get(i).priority < snippets.get(index).priority) {
                    index = i;
                }
            }
            ApkCodeContext.Snippet removed = snippets.remove(index);
            seen.remove(removed.kind + "\0" + removed.text);
        }

        ApkCodeContext build() {
            snippets.sort(Comparator
                    .comparingInt((ApkCodeContext.Snippet snippet) -> -snippet.priority)
                    .thenComparing(snippet -> snippet.kind)
                    .thenComparing(snippet -> snippet.text));
            return new ApkCodeContext(
                    new ArrayList<>(nativeLibraries),
                    new ArrayList<>(assets),
                    new ArrayList<>(resources),
                    new ArrayList<>(snippets),
                    new ArrayList<>(notes),
                    dexFiles,
                    entriesSeen,
                    stringsVisited,
                    resourceFiles,
                    manifestPresent,
                    truncated);
        }
    }
}
