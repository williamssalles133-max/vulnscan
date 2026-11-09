package com.williams.vulnscan.model;

public enum Severity {
    ALTO,
    MEDIO,
    BAIXO,
    INFO;

    public String label() {
        return switch (this) {
            case ALTO -> "Alto";
            case MEDIO -> "Médio";
            case BAIXO -> "Baixo";
            case INFO -> "Info";
        };
    }
}
