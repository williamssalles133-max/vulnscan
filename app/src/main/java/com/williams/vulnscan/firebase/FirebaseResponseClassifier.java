package com.williams.vulnscan.firebase;

import com.williams.vulnscan.model.ProbeResult;

import java.util.Locale;

public final class FirebaseResponseClassifier {
    private FirebaseResponseClassifier() {
    }

    public static ProbeResult firestoreRead(int code, String body) {
        return classifyFirestore("Cloud Firestore (leitura)", code, body, true);
    }

    public static ProbeResult firestoreWrite(int code, String body) {
        return classifyFirestore("Cloud Firestore (escrita)", code, body, false);
    }

    public static ProbeResult realtime(int code, String body) {
        String target = "Realtime Database";
        String lower = lower(body);
        if (invalidKey(lower)) {
            return error(target, code, "A Web API key foi recusada. Confira a chave do app Web no console do Firebase.");
        }
        if (code == 200 && lower.contains("permission denied")) {
            return protectedResult(target, code,
                    "A leitura sem autenticação foi recusada. O Realtime Database bloqueou o cliente anônimo.");
        }
        if (code == 200) {
            String extra = body != null && body.trim().equals("null")
                    ? " A raiz respondeu null, mas a leitura foi autorizada."
                    : "";
            return open(target, code,
                    "A leitura de /.json?shallow=true foi aceita sem autenticação. As regras permitem leitura pública da raiz. As chaves retornadas não são mostradas aqui. Exija auth != null na regra .read."
                            + extra);
        }
        if (code == 401 || code == 403) {
            return protectedResult(target, code,
                    "A leitura sem autenticação foi recusada. O Realtime Database está protegido contra cliente anônimo.");
        }
        if (code == 404) {
            return inconclusive(target, code,
                    "O Realtime Database não foi encontrado nesse endereço. Confira a URL no console.");
        }
        if (code == 423) {
            return inconclusive(target, code, "O banco respondeu 423 e a sondagem não classificou as regras.");
        }
        return unexpected(target, code);
    }

    public static ProbeResult storage(String target, int code, String body) {
        String lower = lower(body);
        if (invalidKey(lower)) {
            return error(target, code, "A Web API key foi recusada. Confira a chave do app Web no console do Firebase.");
        }
        if (apiDisabled(lower)) {
            return inconclusive(target, code,
                    "A API de Storage parece desativada neste projeto. Isso não prova que as regras estão abertas.");
        }
        if (code == 200) {
            return open(target, code,
                    "A listagem do bucket foi aceita sem autenticação. Arquivos podem estar expostos. Restrinja as regras de Storage. Os nomes dos arquivos não são mostrados aqui.");
        }
        if (code == 401 || code == 403) {
            return protectedResult(target, code, "A listagem do bucket foi recusada sem autenticação.");
        }
        if (code == 404) {
            return inconclusive(target, code, "O bucket não existe ou não está acessível nesse nome.");
        }
        return unexpected(target, code);
    }

    private static ProbeResult classifyFirestore(String target, int code, String body, boolean read) {
        String lower = lower(body);
        if (invalidKey(lower)) {
            return error(target, code, "A Web API key foi recusada. Confira a chave do app Web no console do Firebase.");
        }
        if (apiDisabled(lower)) {
            return inconclusive(target, code,
                    "A API Cloud Firestore parece desativada ou ainda não foi usada neste projeto. Isso não prova que as regras estão abertas.");
        }
        if (code == 200) {
            if (read) {
                return open(target, code,
                        "A leitura sem autenticação foi aceita na coleção vulnscan_probe. Quem tiver o project id e a Web API key pode ler esse caminho se as regras forem iguais para o restante do banco. Feche as regras de read.");
            }
            return open(target, code,
                    "A escrita sem autenticação foi aceita. Um documento pequeno foi criado na coleção vulnscan_probe. Apague esse documento no console e exija autenticação nas regras de create/write.");
        }
        if (code == 401 || code == 403) {
            if (read) {
                return protectedResult(target, code,
                        "A leitura sem autenticação foi recusada. As regras ou o IAM bloquearam o cliente anônimo. Esse é o comportamento esperado para dados privados.");
            }
            return protectedResult(target, code,
                    "A escrita sem autenticação foi recusada. O cliente anônimo não conseguiu criar um documento.");
        }
        if (code == 404) {
            return inconclusive(target, code, "O projeto ou o banco (default) não foi encontrado. Confira o project id.");
        }
        if (code == 400) {
            return error(target, code, "O Firestore recusou a requisição. Confira o project id e a API key.");
        }
        return unexpected(target, code);
    }

    private static boolean invalidKey(String lower) {
        return lower.contains("api key not valid")
                || lower.contains("api_key_invalid")
                || lower.contains("invalid api key");
    }

    private static boolean apiDisabled(String lower) {
        return lower.contains("has not been used")
                || lower.contains("service_disabled")
                || lower.contains("it is disabled")
                || lower.contains("api has not been used");
    }

    private static String lower(String body) {
        return body == null ? "" : body.toLowerCase(Locale.ROOT);
    }

    private static ProbeResult open(String target, int code, String message) {
        return new ProbeResult(target, ProbeResult.Status.ABERTO, code, http(code, message));
    }

    private static ProbeResult protectedResult(String target, int code, String message) {
        return new ProbeResult(target, ProbeResult.Status.PROTEGIDO, code, http(code, message));
    }

    private static ProbeResult inconclusive(String target, int code, String message) {
        return new ProbeResult(target, ProbeResult.Status.INCONCLUSIVO, code, http(code, message));
    }

    private static ProbeResult error(String target, int code, String message) {
        return new ProbeResult(target, ProbeResult.Status.ERRO, code, http(code, message));
    }

    private static ProbeResult unexpected(String target, int code) {
        return error(target, code, "Resposta inesperada. A sondagem não classificou o resultado como aberto ou protegido.");
    }

    private static String http(int code, String message) {
        if (code <= 0) {
            return message;
        }
        return "HTTP " + code + ". " + message;
    }
}
