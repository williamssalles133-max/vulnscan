package com.williams.vulnscan.model;

public final class ProbeResult {
    public enum Status {
        ABERTO,
        PROTEGIDO,
        INCONCLUSIVO,
        ERRO
    }

    public final String target;
    public final Status status;
    public final int httpCode;
    public final String explanation;

    public ProbeResult(String target, Status status, int httpCode, String explanation) {
        this.target = target;
        this.status = status;
        this.httpCode = httpCode;
        this.explanation = explanation;
    }

    public String badge() {
        return switch (status) {
            case ABERTO -> "ABERTO (vulnerável)";
            case PROTEGIDO -> "PROTEGIDO";
            case INCONCLUSIVO -> "INCONCLUSIVO";
            case ERRO -> "ERRO";
        };
    }
}
