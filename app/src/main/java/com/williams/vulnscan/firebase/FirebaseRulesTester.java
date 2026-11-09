package com.williams.vulnscan.firebase;

import com.williams.vulnscan.Text;
import com.williams.vulnscan.model.FirebaseHints;
import com.williams.vulnscan.model.ProbeResult;

import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLException;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

public final class FirebaseRulesTester {
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private final OkHttpClient client;

    public FirebaseRulesTester() {
        this(new OkHttpClient.Builder()
                .connectTimeout(20, TimeUnit.SECONDS)
                .readTimeout(25, TimeUnit.SECONDS)
                .writeTimeout(20, TimeUnit.SECONDS)
                .callTimeout(40, TimeUnit.SECONDS)
                .followRedirects(false)
                .followSslRedirects(false)
                .build());
    }

    FirebaseRulesTester(OkHttpClient client) {
        this.client = client;
    }

    public List<ProbeResult> test(FirebaseHints config) {
        List<ProbeResult> results = new ArrayList<>();
        boolean wantsFirestore = !Text.isBlank(config.projectId) || !Text.isBlank(config.apiKey);
        String project = FirebaseTargets.normalizeProjectId(config.projectId);
        String key = FirebaseTargets.normalizeApiKey(config.apiKey);
        if (wantsFirestore) {
            if (project == null) {
                results.add(localError("Cloud Firestore (leitura)",
                        "Project id inválido. Use o identificador do console, só com letras minúsculas, números e hífen."));
                results.add(localError("Cloud Firestore (escrita)",
                        "Escrita não executada porque o project id é inválido."));
            } else if (key == null) {
                results.add(localError("Cloud Firestore (leitura)",
                        "Web API key inválida. Cole a chave Web do app, em geral começando com AIza."));
                results.add(localError("Cloud Firestore (escrita)",
                        "Escrita não executada porque a Web API key é inválida."));
            } else {
                String readUrl = firestoreUrl(project, key, true);
                String writeUrl = firestoreUrl(project, key, false);
                results.add(safe("Cloud Firestore (leitura)", () -> {
                    HttpResult http = request("GET", readUrl, null);
                    return FirebaseResponseClassifier.firestoreRead(http.code, http.body);
                }));
                results.add(safe("Cloud Firestore (escrita)", () -> {
                    HttpResult http = request("POST", writeUrl, writeBody());
                    return FirebaseResponseClassifier.firestoreWrite(http.code, http.body);
                }));
                String bucket = FirebaseTargets.normalizeBucket(config.storageBucket);
                boolean guessed = false;
                if (bucket == null) {
                    bucket = project + ".appspot.com";
                    guessed = true;
                }
                String storageTarget = guessed
                        ? "Cloud Storage (bucket presumido)"
                        : "Cloud Storage";
                String bucketName = bucket;
                results.add(safe(storageTarget, () -> {
                    String url = "https://firebasestorage.googleapis.com/v0/b/"
                            + urlEncode(bucketName)
                            + "/o?maxResults=1&key="
                            + urlEncode(key);
                    HttpResult http = request("GET", url, null);
                    return FirebaseResponseClassifier.storage(storageTarget, http.code, http.body);
                }));
            }
        }

        if (!Text.isBlank(config.databaseUrl)) {
            String database = FirebaseTargets.normalizeDatabaseUrl(config.databaseUrl);
            if (database == null) {
                results.add(localError("Realtime Database",
                        "A URL precisa ser de um Realtime Database (firebaseio.com ou firebasedatabase.app)."));
            } else {
                results.add(safe("Realtime Database", () -> {
                    HttpResult http = request("GET", database + "/.json?shallow=true", null);
                    return FirebaseResponseClassifier.realtime(http.code, http.body);
                }));
            }
        } else if (!wantsFirestore) {
            results.add(new ProbeResult(
                    "Firebase",
                    ProbeResult.Status.INCONCLUSIVO,
                    -1,
                    "Informe o project id e a Web API key, ou uma URL de Realtime Database."));
        } else {
            results.add(new ProbeResult(
                    "Realtime Database",
                    ProbeResult.Status.INCONCLUSIVO,
                    -1,
                    "Nenhuma URL de Realtime Database informada. A sondagem foi ignorada."));
        }
        return results;
    }

    private static String firestoreUrl(String projectId, String apiKey, boolean list) {
        String url = "https://firestore.googleapis.com/v1/projects/"
                + projectId
                + "/databases/%28default%29/documents/vulnscan_probe?key="
                + urlEncode(apiKey);
        if (list) {
            url += "&pageSize=1";
        }
        return url;
    }

    private static String writeBody() {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        String stamp = format.format(new Date());
        return "{\"fields\":{"
                + "\"origem\":{\"stringValue\":\"VulnScan\"},"
                + "\"tipo\":{\"stringValue\":\"sonda inofensiva\"},"
                + "\"aviso\":{\"stringValue\":\"Criado porque a escrita anonima foi aceita. Pode apagar.\"},"
                + "\"quando\":{\"stringValue\":\"" + stamp + "\"}"
                + "}}";
    }

    private ProbeResult safe(String target, Call call) {
        try {
            return call.run();
        } catch (IllegalArgumentException ex) {
            return localError(target, "URL inválida para a sondagem.");
        } catch (SocketTimeoutException ex) {
            return localError(target, "Tempo esgotado ao contatar o serviço. Verifique a rede.");
        } catch (UnknownHostException ex) {
            return localError(target, "Não foi possível resolver o endereço. Verifique a rede ou o nome do projeto.");
        } catch (SSLException ex) {
            return localError(target, "Falha de TLS ao conectar no serviço.");
        } catch (IOException ex) {
            return localError(target, "Erro de rede ao consultar o serviço.");
        }
    }

    private HttpResult request(String method, String url, String json) throws IOException {
        Request.Builder builder = new Request.Builder()
                .url(url)
                .header("Accept", "application/json")
                .header("User-Agent", "VulnScan/1.0");
        if ("POST".equals(method)) {
            builder.post(RequestBody.create(json == null ? "{}" : json, JSON));
        } else {
            builder.get();
        }
        try (Response response = client.newCall(builder.build()).execute()) {
            int code = response.code();
            if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                return new HttpResult(code, "redirect");
            }
            return new HttpResult(code, readLimited(response.body()));
        }
    }

    private static String readLimited(ResponseBody body) throws IOException {
        if (body == null) {
            return "";
        }
        try (InputStream in = body.byteStream()) {
            byte[] buffer = new byte[4096];
            StringBuilder builder = new StringBuilder();
            int total = 0;
            int read;
            while ((read = in.read(buffer)) >= 0 && total < 65536) {
                int take = Math.min(read, 65536 - total);
                builder.append(new String(buffer, 0, take, StandardCharsets.UTF_8));
                total += take;
            }
            return builder.toString();
        }
    }

    private static ProbeResult localError(String target, String message) {
        return new ProbeResult(target, ProbeResult.Status.ERRO, -1, message);
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException ex) {
            return value;
        }
    }

    private interface Call {
        ProbeResult run() throws IOException;
    }

    private static final class HttpResult {
        final int code;
        final String body;

        HttpResult(int code, String body) {
            this.code = code;
            this.body = body;
        }
    }
}
