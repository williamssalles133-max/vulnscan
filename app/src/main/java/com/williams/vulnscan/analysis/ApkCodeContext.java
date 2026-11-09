package com.williams.vulnscan.analysis;

import java.util.Collections;
import java.util.List;

/** Extrato somente leitura de um APK, já limitado, para o parecer da IA. */
public final class ApkCodeContext {
    public final List<String> nativeLibraries;
    public final List<String> assets;
    public final List<String> resources;
    public final List<Snippet> snippets;
    public final List<String> notes;
    public final int dexFiles;
    public final int entriesSeen;
    public final int stringsVisited;
    public final int resourceFiles;
    public final boolean manifestPresent;
    public final boolean truncated;

    public ApkCodeContext(
            List<String> nativeLibraries,
            List<String> assets,
            List<String> resources,
            List<Snippet> snippets,
            List<String> notes,
            int dexFiles,
            int entriesSeen,
            int stringsVisited,
            int resourceFiles,
            boolean manifestPresent,
            boolean truncated) {
        this.nativeLibraries = Collections.unmodifiableList(nativeLibraries);
        this.assets = Collections.unmodifiableList(assets);
        this.resources = Collections.unmodifiableList(resources);
        this.snippets = Collections.unmodifiableList(snippets);
        this.notes = Collections.unmodifiableList(notes);
        this.dexFiles = dexFiles;
        this.entriesSeen = entriesSeen;
        this.stringsVisited = stringsVisited;
        this.resourceFiles = resourceFiles;
        this.manifestPresent = manifestPresent;
        this.truncated = truncated;
    }

    public static final class Snippet {
        public final String file;
        public final String kind;
        public final String text;
        public final int priority;

        public Snippet(String file, String kind, String text, int priority) {
            this.file = file;
            this.kind = kind;
            this.text = text;
            this.priority = priority;
        }
    }
}
