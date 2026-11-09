package com.williams.vulnscan.ai;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

public final class AiClient {
    public static final class AiException extends Exception {
        public AiException(String message) {
            super(message);
        }
    }

    private static final String ENDPOINT = "https://api.x.ai/v1/chat/completions";
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String SYSTEM_PROMPT = """
            Você é um especialista em segurança de aplicativos Android.
            O JSON a seguir é o resultado de uma varredura feita pelo próprio desenvolvedor no aplicativo dele (teste autorizado).
            Para cada achado: explique o risco em português claro, indique a severidade (Alto, Médio, Baixo ou Info) e descreva como corrigir no código ou na configuração (manifesto, regras do Firebase, rotação de chave).
            Agrupe por severidade. Não invente vulnerabilidades que não estejam no JSON.
            Se uma sonda Firebase estiver ABERTO, trate como exposição real de dados e explique como fechar as regras.
            Segredos já chegam mascarados: não peça o valor completo.
            Seja direto e prático. Responda em Markdown.""";

    private final OkHttpClient client;

    public AiClient() {
        this(new OkHttpClient.Builder()
                .connectTimeout(20, TimeUnit.SECONDS)
                .readTimeout(90, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .callTimeout(120, TimeUnit.SECONDS)
                .followRedirects(false)
                .build());
    }

    AiClient(OkHttpClient client) {
        this.client = client;
    }

    public String analyze(String apiKey, String summaryJson) throws AiException, IOException {
        if (apiKey == null || apiKey.trim().isEmpty()) {
            throw new AiException("Nenhuma chave de API informada.");
        }
        String key = apiKey.trim();
        if (!key.startsWith("xai-")) {
            throw new AiException("A chave parece inválida. Ela deve começar com xai- (cole a chave completa da Grok API).");
        }
        try {
            return complete(key, "grok-4.7", summaryJson);
        } catch (ModelMissing missing) {
            try {
                return complete(key, "grok-4.3", summaryJson);
            } catch (ModelMissing again) {
                throw new AiException("Nenhum dos modelos grok-4.7 ou grok-4.3 foi aceito pela API xAI.");
            }
        }
    }

    private String complete(String apiKey, String model, String summaryJson) throws AiException, IOException, ModelMissing {
        JSONObject body = new JSONObject();
        try {
            body.put("model", model);
            body.put("temperature", 0.2);
            body.put("stream", false);
            JSONArray messages = new JSONArray();
            messages.put(new JSONObject().put("role", "system").put("content", SYSTEM_PROMPT));
            messages.put(new JSONObject()
                    .put("role", "user")
                    .put("content", "Resumo da varredura:\n" + summaryJson));
            body.put("messages", messages);
        } catch (JSONException ex) {
            throw new AiException("Não foi possível montar o pedido para a IA.");
        }
        Request request = new Request.Builder()
                .url(ENDPOINT)
                .header("Authorization", "Bearer " + apiKey)
                .header("Accept", "application/json")
                .header("User-Agent", "VulnScan/1.0")
                .post(RequestBody.create(body.toString(), JSON))
                .build();
        try (Response response = client.newCall(request).execute()) {
            String payload = response.body() == null ? "" : readLimited(response.body());
            int code = response.code();
            if (modelMissing(code, payload)) {
                throw new ModelMissing();
            }
            if (code < 200 || code >= 300) {
                throw new AiException(httpError(code, payload));
            }
            return extractContent(payload);
        }
    }

    private static String extractContent(String payload) throws AiException {
        try {
            JSONObject root = new JSONObject(payload);
            JSONArray choices = root.optJSONArray("choices");
            if (choices != null && choices.length() > 0) {
                JSONObject message = choices.getJSONObject(0).optJSONObject("message");
                if (message != null) {
                    String content = message.optString("content", "").trim();
                    if (!content.isEmpty()) {
                        return content;
                    }
                }
            }
        } catch (JSONException ex) {
            throw new AiException("A resposta da IA veio em um formato inesperado.");
        }
        throw new AiException("A resposta da IA veio em um formato inesperado.");
    }

    private static boolean modelMissing(int code, String body) {
        if (code == 404) {
            return true;
        }
        if (code != 400 && code != 422) {
            return false;
        }
        String lower = body == null ? "" : body.toLowerCase(Locale.ROOT);
        return lower.contains("model")
                && (lower.contains("not found")
                || lower.contains("does not exist")
                || lower.contains("unknown")
                || lower.contains("not available")
                || lower.contains("invalid")
                || lower.contains("incorrect")
                || lower.contains("unsupported"));
    }

    private static String httpError(int code, String body) {
        String snippet = body == null ? "" : body.replaceAll("\\s+", " ").trim();
        if (snippet.length() > 180) {
            snippet = snippet.substring(0, 180) + "…";
        }
        return switch (code) {
            case 401, 403 -> "A chave foi recusada pela API xAI (HTTP " + code + "). Confira se ela está correta e ativa.";
            case 404 -> "O modelo não foi encontrado (HTTP 404).";
            case 429 -> "A API xAI limitou as requisições (HTTP 429). Espere um pouco e tente de novo.";
            case 400 -> "A API xAI recusou o pedido (HTTP 400). " + snippet;
            default -> "Falha ao consultar a IA (HTTP " + code + "). " + snippet;
        };
    }

    private static String readLimited(ResponseBody body) throws IOException {
        String text = body.string();
        if (text.length() > 200_000) {
            return text.substring(0, 200_000);
        }
        return text;
    }

    private static final class ModelMissing extends Exception {
    }
}
