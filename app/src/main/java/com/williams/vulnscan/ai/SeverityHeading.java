package com.williams.vulnscan.ai;

import java.util.Locale;

/** Reconhece títulos de severidade no Markdown do parecer (Alto, Médio, Baixo, Informativo). */
public final class SeverityHeading {
    public enum Level {
        ALTO,
        MEDIO,
        BAIXO,
        INFO
    }

    private SeverityHeading() {
    }

    public static Level parse(String heading) {
        if (heading == null) {
            return null;
        }
        String normalized = heading.trim().toLowerCase(Locale.ROOT).replace("*", "").replace("`", "");
        if (startsWord(normalized, "alto")) {
            return Level.ALTO;
        }
        if (startsWord(normalized, "médio") || startsWord(normalized, "medio")) {
            return Level.MEDIO;
        }
        if (startsWord(normalized, "baixo")) {
            return Level.BAIXO;
        }
        if (startsWord(normalized, "informativo") || startsWord(normalized, "info")) {
            return Level.INFO;
        }
        return null;
    }

    private static boolean startsWord(String text, String word) {
        if (!text.startsWith(word)) {
            return false;
        }
        if (text.length() == word.length()) {
            return true;
        }
        char next = text.charAt(word.length());
        return next == ' ' || next == ':' || next == '-' || next == '—' || next == '–' || next == '.';
    }
}
