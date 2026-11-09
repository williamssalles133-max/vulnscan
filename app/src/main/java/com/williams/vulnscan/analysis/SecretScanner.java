package com.williams.vulnscan.analysis;

import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.FirebaseHints;
import com.williams.vulnscan.model.Severity;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Varre o APK por strings imprimíveis. Não faz parse completo de DEX:
 * chaves e URLs aparecem como texto cru em classes.dex, no manifesto binário e em assets.
 */
public final class SecretScanner {
    private static final int MAX_ENTRY_BYTES = 32 * 1024 * 1024;
    private static final int MIN_STRING = 8;
    private static final int MAX_RAWS = 400;

    private static final Pattern GOOGLE_API = Pattern.compile("AIza[0-9A-Za-z_\\-]{35}");
    private static final Pattern FIREBASE_IO = Pattern.compile(
            "https?://[a-z0-9\\-]+\\.firebaseio\\.com", Pattern.CASE_INSENSITIVE);
    private static final Pattern FIREBASE_DB_APP = Pattern.compile(
            "https?://[a-z0-9.\\-]+\\.firebasedatabase\\.app", Pattern.CASE_INSENSITIVE);
    private static final Pattern FIREBASE_APP = Pattern.compile(
            "https?://[a-z0-9\\-]+\\.firebaseapp\\.com", Pattern.CASE_INSENSITIVE);
    private static final Pattern FIRESTORE = Pattern.compile(
            "https?://firestore\\.googleapis\\.com", Pattern.CASE_INSENSITIVE);
    private static final Pattern BUCKET_APPSPOT = Pattern.compile(
            "\\b[a-z0-9][a-z0-9\\-]{2,}\\.appspot\\.com\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern BUCKET_FS = Pattern.compile(
            "\\b[a-z0-9][a-z0-9\\-]{2,}\\.firebasestorage\\.app\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern PROJECT_ID = Pattern.compile(
            "\"project_id\"\\s*:\\s*\"([a-z0-9\\-]{6,30})\"");
    private static final Pattern PRIVATE_KEY = Pattern.compile(
            "-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----");
    private static final Pattern AWS = Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b");
    private static final Pattern JWT = Pattern.compile(
            "eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}");
    private static final Pattern STRIPE = Pattern.compile("\\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\\b");
    private static final Pattern GITHUB = Pattern.compile(
            "\\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\\b");
    private static final Pattern SLACK = Pattern.compile("\\bxox[baprs]-[A-Za-z0-9\\-]{10,}");
    private static final Pattern GENERIC = Pattern.compile(
            "(?i)\\b(?:api[_\\-]?key|api[_\\-]?secret|secret[_\\-]?key|access[_\\-]?token|client[_\\-]?secret|auth[_\\-]?token)\\b[\\s\"'`:={]{1,16}([A-Za-z0-9_\\-./+=]{20,120})");
    private static final Pattern PASSWORD = Pattern.compile(
            "(?i)\\b(?:password|passwd|senha)\\b[\\s\"'`:={]{1,16}([^\\s\"'<>]{8,64})");

    public static final class Result {
        public final List<Finding> findings;
        public final FirebaseHints hints;

        public Result(List<Finding> findings, FirebaseHints hints) {
            this.findings = findings;
            this.hints = hints;
        }
    }

    public Result scan(File apk) throws IOException {
        List<Raw> raws = new ArrayList<>();
        boolean skippedLarge = false;
        try (ZipFile zip = new ZipFile(apk)) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !shouldScan(entry.getName())) {
                    continue;
                }
                if (entry.getSize() > MAX_ENTRY_BYTES) {
                    skippedLarge = true;
                    continue;
                }
                byte[] data;
                try (InputStream in = zip.getInputStream(entry)) {
                    data = readCapped(in, MAX_ENTRY_BYTES);
                } catch (IOException ignored) {
                    continue;
                }
                if (data == null) {
                    skippedLarge = true;
                    continue;
                }
                scanBytes(data, entry.getName(), wantsUtf16(entry.getName()), raws);
                if (raws.size() >= MAX_RAWS) {
                    break;
                }
            }
        }
        Result result = toResult(raws);
        if (skippedLarge) {
            List<Finding> withNote = new ArrayList<>(result.findings);
            withNote.add(new Finding(
                    Severity.INFO,
                    "Segredo",
                    "Arquivo grande ignorado",
                    "Um ou mais arquivos do APK passaram de 32 MB e não entraram na busca por segredos.",
                    apk.getName(),
                    null));
            return new Result(withNote, result.hints);
        }
        return result;
    }

    static boolean shouldScan(String name) {
        String lower = name.toLowerCase(Locale.US);
        if (lower.contains("..") || lower.startsWith("lib/") || lower.startsWith("meta-inf/") || lower.startsWith("kotlin/")) {
            return false;
        }
        if (isMedia(extension(lower))) {
            return false;
        }
        if (lower.equals("androidmanifest.xml") || lower.equals("resources.arsc")) {
            return true;
        }
        if (lower.startsWith("classes") && lower.endsWith(".dex")) {
            return true;
        }
        return lower.startsWith("res/") || lower.startsWith("assets/");
    }

    private static boolean wantsUtf16(String name) {
        String lower = name.toLowerCase(Locale.US);
        return lower.equals("androidmanifest.xml")
                || lower.equals("resources.arsc")
                || lower.endsWith(".xml");
    }

    private void scanBytes(byte[] data, String location, boolean utf16, List<Raw> raws) {
        walkAscii(data, value -> collect(value, location, raws));
        if (utf16 && raws.size() < MAX_RAWS) {
            walkUtf16(data, 0, value -> collect(value, location, raws));
            walkUtf16(data, 1, value -> collect(value, location, raws));
        }
    }

    private void collect(String text, String location, List<Raw> raws) {
        if (raws.size() >= MAX_RAWS || text.length() < MIN_STRING || !maybeInteresting(text)) {
            return;
        }
        findAll(GOOGLE_API, text, match -> add(raws, "google_api_key", match, location));
        findAll(FIREBASE_IO, text, match -> add(raws, "firebase_rtdb", origin(match), location));
        findAll(FIREBASE_DB_APP, text, match -> add(raws, "firebase_rtdb", origin(match), location));
        findAll(FIREBASE_APP, text, match -> add(raws, "firebase_app", origin(match), location));
        findAll(FIRESTORE, text, match -> add(raws, "firestore", "https://firestore.googleapis.com", location));
        findAll(BUCKET_APPSPOT, text, match -> add(raws, "bucket", match.toLowerCase(Locale.US), location));
        findAll(BUCKET_FS, text, match -> add(raws, "bucket", match.toLowerCase(Locale.US), location));
        findGroups(PROJECT_ID, text, value -> add(raws, "project_id", value, location));
        findAll(PRIVATE_KEY, text, match -> add(raws, "private_key", match, location));
        findAll(AWS, text, match -> add(raws, "aws", match, location));
        findAll(JWT, text, match -> {
            if (validJwt(match)) {
                add(raws, "jwt", match, location);
            }
        });
        findAll(STRIPE, text, match -> add(raws, "generic", match, location));
        findAll(GITHUB, text, match -> add(raws, "generic", match, location));
        findAll(SLACK, text, match -> add(raws, "generic", match, location));
        findGroups(GENERIC, text, value -> {
            String token = cleanToken(value);
            if (token.startsWith("AIza") || placeholder(token) || !mixedToken(token)) {
                return;
            }
            add(raws, "generic", token, location);
        });
        findGroups(PASSWORD, text, value -> {
            String token = cleanToken(value);
            if (placeholder(token)) {
                return;
            }
            add(raws, "password", token, location);
        });
    }

    private static void add(List<Raw> raws, String type, String value, String location) {
        if (value == null || value.isEmpty() || raws.size() >= MAX_RAWS) {
            return;
        }
        raws.add(new Raw(type, value, location));
    }

    private Result toResult(List<Raw> raws) {
        Map<String, Agg> grouped = new LinkedHashMap<>();
        Map<String, Integer> apiCounts = new HashMap<>();
        Map<String, Integer> projectCounts = new HashMap<>();
        Map<String, Integer> dbCounts = new HashMap<>();
        Map<String, Integer> bucketCounts = new HashMap<>();
        for (Raw raw : raws) {
            String key = raw.type + "\u0000" + raw.value;
            grouped.computeIfAbsent(key, ignored -> new Agg(raw)).locations.add(raw.location);
            switch (raw.type) {
                case "google_api_key" -> apiCounts.merge(raw.value, 1, Integer::sum);
                case "project_id" -> projectCounts.merge(raw.value, 1, Integer::sum);
                case "firebase_rtdb" -> dbCounts.merge(raw.value, 1, Integer::sum);
                case "bucket" -> bucketCounts.merge(raw.value, 1, Integer::sum);
                default -> {
                }
            }
        }

        List<Finding> findings = new ArrayList<>();
        int genericShown = 0;
        int passwordShown = 0;
        int genericHidden = 0;
        int passwordHidden = 0;
        boolean firestoreNoted = false;
        for (Agg agg : grouped.values()) {
            String where = locations(agg.locations);
            switch (agg.type) {
                case "google_api_key" -> findings.add(new Finding(
                        Severity.ALTO,
                        "Segredo",
                        "Chave de API Google embutida",
                        "Chave começando com AIza encontrada no pacote. Quem descompilar o APK consegue copiá-la e consumir cota ou chamar APIs liberadas para essa chave. Restrinja a chave pelo pacote e pelo SHA-256 do certificado e, se ela já foi publicada, rotacione.",
                        where,
                        agg.value));
                case "private_key" -> findings.add(new Finding(
                        Severity.ALTO,
                        "Segredo",
                        "Chave privada embutida",
                        "Há um bloco de chave privada no pacote. Qualquer pessoa extrai o APK e assume essa identidade. Remova o bloco, revogue a chave e use um cofre no servidor.",
                        where,
                        agg.value));
                case "aws" -> {
                    if (agg.value.contains("EXAMPLE")) {
                        break;
                    }
                    findings.add(new Finding(
                            Severity.ALTO,
                            "Segredo",
                            "Chave de acesso AWS embutida",
                            "Identificador AKIA/ASIA encontrado. Com o segredo correspondente, a conta AWS pode ser usada fora do app. Rotacione a chave e não coloque credencial de nuvem no cliente.",
                            where,
                            agg.value));
                }
                case "jwt" -> findings.add(new Finding(
                        Severity.ALTO,
                        "Segredo",
                        "JSON Web Token embutido",
                        "Um JWT foi encontrado no pacote. Se ainda for válido, pode ser reutilizado para chamar APIs. Token de acesso deve nascer em runtime, não compilado no APK.",
                        where,
                        agg.value));
                case "generic" -> {
                    if (genericShown >= 12) {
                        genericHidden++;
                        break;
                    }
                    genericShown++;
                    findings.add(new Finding(
                            strongSecret(agg.value) ? Severity.ALTO : Severity.MEDIO,
                            "Segredo",
                            "Possível token ou segredo de API",
                            "O texto parece uma credencial (api key, token ou client secret). Confira se é um segredo real. Se for, mova para um backend e rotacione.",
                            where,
                            agg.value));
                }
                case "password" -> {
                    if (passwordShown >= 12) {
                        passwordHidden++;
                        break;
                    }
                    passwordShown++;
                    findings.add(new Finding(
                            strongSecret(agg.value) ? Severity.ALTO : Severity.MEDIO,
                            "Segredo",
                            "Possível senha embutida",
                            "O texto parece atribuir uma senha fixa. Senha no cliente é recuperável. Se for credencial real, troque e autentique via servidor. Pode ser falso positivo de texto de interface.",
                            where,
                            agg.value));
                }
                case "firebase_rtdb" -> findings.add(new Finding(
                        Severity.MEDIO,
                        "Firebase",
                        "URL de Realtime Database no cliente",
                        "Endpoint encontrado: " + agg.value + ". A URL em si não é secreta, mas se as regras permitirem leitura anônima o banco fica público. Teste na aba Firebase.",
                        where,
                        null));
                case "firebase_app" -> findings.add(new Finding(
                        Severity.INFO,
                        "Firebase",
                        "Host Firebase Hosting",
                        "O pacote referencia " + agg.value + ".",
                        where,
                        null));
                case "firestore" -> {
                    if (firestoreNoted) {
                        break;
                    }
                    firestoreNoted = true;
                    findings.add(new Finding(
                            Severity.INFO,
                            "Firebase",
                            "Referência ao Cloud Firestore",
                            "O pacote cita firestore.googleapis.com. A API key do cliente não protege os dados: quem segura o acesso são as regras de segurança.",
                            where,
                            null));
                }
                case "bucket" -> findings.add(new Finding(
                        Severity.MEDIO,
                        "Firebase",
                        "Bucket do Cloud Storage",
                        "Bucket referenciado: " + agg.value + ". Se as regras de Storage permitirem listagem pública, os arquivos ficam expostos.",
                        where,
                        null));
                case "project_id" -> findings.add(new Finding(
                        Severity.INFO,
                        "Firebase",
                        "Project id do Firebase",
                        "Identificador de projeto encontrado: " + agg.value + ". Ele não é segredo, mas identifica o backend que deve ser testado.",
                        where,
                        null));
                default -> {
                }
            }
        }
        if (genericHidden > 0 || passwordHidden > 0) {
            findings.add(new Finding(
                    Severity.INFO,
                    "Segredo",
                    "Achados extras omitidos",
                    "A lista foi limitada para continuar legível. Ainda há "
                            + (genericHidden + passwordHidden)
                            + " correspondências parecidas no pacote.",
                    "APK",
                    null));
        }

        String databaseUrl = preferDatabase(dbCounts);
        String bucket = mostCommon(bucketCounts);
        String project = mostCommon(projectCounts);
        if (!validProject(project)) {
            project = deriveProject(databaseUrl);
        }
        if (!validProject(project)) {
            project = deriveProject(mostCommonHost(grouped, "firebase_app"));
        }
        if (!validProject(project) && bucket != null && bucket.endsWith(".appspot.com")) {
            String label = bucket.substring(0, bucket.length() - ".appspot.com".length());
            if (validProject(label)) {
                project = label;
            }
        }
        if (!validProject(project)) {
            project = null;
        }
        return new Result(findings, new FirebaseHints(project, mostCommon(apiCounts), databaseUrl, bucket));
    }

    private static String mostCommonHost(Map<String, Agg> grouped, String type) {
        Map<String, Integer> counts = new HashMap<>();
        for (Agg agg : grouped.values()) {
            if (type.equals(agg.type)) {
                counts.merge(agg.value, agg.locations.size(), Integer::sum);
            }
        }
        return mostCommon(counts);
    }

    private static String preferDatabase(Map<String, Integer> counts) {
        String bestIo = null;
        int bestIoCount = -1;
        String bestOther = null;
        int bestOtherCount = -1;
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            String url = entry.getKey();
            if (url.contains(".firebaseio.com")) {
                if (entry.getValue() > bestIoCount) {
                    bestIoCount = entry.getValue();
                    bestIo = url;
                }
            } else if (entry.getValue() > bestOtherCount) {
                bestOtherCount = entry.getValue();
                bestOther = url;
            }
        }
        return bestIo != null ? bestIo : bestOther;
    }

    static String deriveProject(String url) {
        if (url == null) {
            return null;
        }
        String host = url;
        int scheme = host.indexOf("://");
        if (scheme >= 0) {
            host = host.substring(scheme + 3);
        }
        int slash = host.indexOf('/');
        if (slash >= 0) {
            host = host.substring(0, slash);
        }
        String lowerHost = host.toLowerCase(Locale.US);
        if (!(lowerHost.endsWith(".firebaseio.com")
                || lowerHost.endsWith(".firebasedatabase.app")
                || lowerHost.endsWith(".firebaseapp.com"))) {
            return null;
        }
        String label = lowerHost.split("\\.")[0];
        if (label.endsWith("-default-rtdb")) {
            label = label.substring(0, label.length() - "-default-rtdb".length());
        }
        return validProject(label) ? label : null;
    }

    static boolean validProject(String value) {
        return value != null && value.matches("[a-z][a-z0-9-]{4,28}[a-z0-9]");
    }

    private static String origin(String url) {
        String value = url.trim();
        int scheme = value.indexOf("://");
        int start = scheme >= 0 ? scheme + 3 : 0;
        int slash = value.indexOf('/', start);
        String host = slash >= 0 ? value.substring(start, slash) : value.substring(start);
        return "https://" + host.toLowerCase(Locale.US);
    }

    private static String locations(Set<String> locations) {
        List<String> list = new ArrayList<>(locations);
        int shown = Math.min(6, list.size());
        String joined = com.williams.vulnscan.Text.join(", ", list.subList(0, shown));
        if (list.size() > shown) {
            joined = joined + " +" + (list.size() - shown);
        }
        return joined;
    }

    private static String mostCommon(Map<String, Integer> counts) {
        String best = null;
        int bestCount = -1;
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            if (entry.getValue() > bestCount) {
                bestCount = entry.getValue();
                best = entry.getKey();
            }
        }
        return best;
    }

    private static boolean maybeInteresting(String value) {
        if (value.indexOf("AIza") >= 0
                || value.indexOf("AKIA") >= 0
                || value.indexOf("ASIA") >= 0
                || value.indexOf("eyJ") >= 0
                || value.indexOf("BEGIN") >= 0
                || value.indexOf("ghp_") >= 0
                || value.indexOf("xox") >= 0) {
            return true;
        }
        String lower = value.toLowerCase(Locale.US);
        return lower.contains("firebase")
                || lower.contains("appspot")
                || lower.contains("project_id")
                || lower.contains("api")
                || lower.contains("secret")
                || lower.contains("token")
                || lower.contains("password")
                || lower.contains("senha")
                || lower.contains("passwd")
                || lower.contains("sk_live")
                || lower.contains("sk_test")
                || lower.contains("rk_live")
                || lower.contains("private key");
    }

    private static boolean placeholder(String value) {
        String lower = value.toLowerCase(Locale.US);
        if (lower.equals("password") || lower.equals("senha") || lower.equals("secret")
                || lower.equals("null") || lower.equals("undefined") || lower.equals("todo")
                || lower.equals("changeme") || lower.equals("example") || lower.equals("placeholder")) {
            return true;
        }
        if (lower.contains("example") || lower.contains("placeholder") || lower.contains("changeme")
                || lower.contains("your_password") || lower.contains("your-password")
                || lower.contains("your_api") || lower.contains("xxxxxxxx") || lower.contains("aaaaaaa")
                || lower.contains("insert_") || lower.contains("${") || lower.contains("%s")
                || lower.contains("****")) {
            return true;
        }
        return lower.chars().distinct().count() < 4;
    }

    private static boolean mixedToken(String value) {
        boolean letter = false;
        boolean digit = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isLetter(c)) {
                letter = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            }
        }
        return letter && digit;
    }

    private static boolean strongSecret(String value) {
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isLowerCase(c)) {
                lower = true;
            } else if (Character.isUpperCase(c)) {
                upper = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            }
        }
        int classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0);
        return value.length() >= 10 && classes >= 2;
    }

    private static boolean validJwt(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 3) {
            return false;
        }
        try {
            byte[] decoded = decodeUrlBase64(parts[0]);
            String json = new String(decoded, StandardCharsets.UTF_8);
            return json.contains("\"alg\"");
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static final int[] BASE64 = new int[128];

    static {
        Arrays.fill(BASE64, -1);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < alphabet.length(); i++) {
            BASE64[alphabet.charAt(i)] = i;
        }
    }

    /** Decodificador pequeno para o cabeçalho do JWT. Evita java.util.Base64, ausente na API 24. */
    private static byte[] decodeUrlBase64(String raw) {
        String value = raw.replace('-', '+').replace('_', '/');
        int mod = value.length() % 4;
        if (mod != 0) {
            value = value + "====".substring(mod);
        }
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == '=') {
            end--;
        }
        byte[] out = new byte[end * 6 / 8];
        int buffer = 0;
        int bits = 0;
        int written = 0;
        for (int i = 0; i < end; i++) {
            char c = value.charAt(i);
            int decoded = c < 128 ? BASE64[c] : -1;
            if (decoded < 0 || written >= out.length) {
                throw new IllegalArgumentException("base64");
            }
            buffer = (buffer << 6) | decoded;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                if (written >= out.length) {
                    throw new IllegalArgumentException("base64");
                }
                out[written++] = (byte) ((buffer >> bits) & 0xff);
            }
        }
        return written == out.length ? out : Arrays.copyOf(out, written);
    }

    private static String cleanToken(String value) {
        String cleaned = value.trim();
        while (!cleaned.isEmpty()) {
            char last = cleaned.charAt(cleaned.length() - 1);
            if (".,;)]}>\"'`".indexOf(last) < 0) {
                break;
            }
            cleaned = cleaned.substring(0, cleaned.length() - 1);
        }
        return cleaned;
    }

    private interface Hit {
        void accept(String value);
    }

    private static void findAll(Pattern pattern, String text, Hit hit) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            hit.accept(matcher.group());
        }
    }

    private static void findGroups(Pattern pattern, String text, Hit hit) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            if (matcher.groupCount() >= 1 && matcher.group(1) != null) {
                hit.accept(matcher.group(1));
            }
        }
    }

    private interface Sink {
        void accept(String value);
    }

    private static void walkAscii(byte[] data, Sink sink) {
        int start = -1;
        for (int i = 0; i <= data.length; i++) {
            boolean printable = i < data.length && data[i] >= 32 && data[i] < 127;
            if (printable) {
                if (start < 0) {
                    start = i;
                }
            } else if (start >= 0) {
                emit(data, start, i, sink);
                start = -1;
            }
        }
    }

    private static void walkUtf16(byte[] data, int align, Sink sink) {
        StringBuilder builder = new StringBuilder();
        for (int i = align; i + 1 < data.length; i += 2) {
            char c = (char) ((data[i] & 0xff) | ((data[i + 1] & 0xff) << 8));
            if (c >= 32 && c < 127) {
                builder.append(c);
                if (builder.length() >= 100_000) {
                    sink.accept(builder.toString());
                    builder.setLength(0);
                }
            } else if (builder.length() >= MIN_STRING) {
                sink.accept(builder.toString());
                builder.setLength(0);
            } else {
                builder.setLength(0);
            }
        }
        if (builder.length() >= MIN_STRING) {
            sink.accept(builder.toString());
        }
    }

    private static void emit(byte[] data, int start, int end, Sink sink) {
        int length = end - start;
        if (length < MIN_STRING) {
            return;
        }
        if (length <= 100_000) {
            sink.accept(new String(data, start, length, StandardCharsets.ISO_8859_1));
            return;
        }
        int window = 80_000;
        int overlap = 4_000;
        for (int i = start; i < end; i += window) {
            int stop = Math.min(end, i + window + overlap);
            sink.accept(new String(data, i, stop - i, StandardCharsets.ISO_8859_1));
            if (stop == end) {
                break;
            }
        }
    }

    private static byte[] readCapped(InputStream in, int cap) throws IOException {
        byte[] buffer = new byte[16384];
        byte[] data = new byte[Math.min(cap, 64 * 1024)];
        int total = 0;
        int read;
        while ((read = in.read(buffer)) >= 0) {
            if (total + read > cap) {
                return null;
            }
            if (total + read > data.length) {
                byte[] grown = new byte[Math.min(cap, Math.max(data.length * 2, total + read))];
                System.arraycopy(data, 0, grown, 0, total);
                data = grown;
            }
            System.arraycopy(buffer, 0, data, total, read);
            total += read;
        }
        if (total == data.length) {
            return data;
        }
        byte[] exact = new byte[total];
        System.arraycopy(data, 0, exact, 0, total);
        return exact;
    }

    private static String extension(String name) {
        int slash = name.lastIndexOf('/');
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot < slash) {
            return "";
        }
        return name.substring(dot + 1);
    }

    private static boolean isMedia(String extension) {
        return switch (extension) {
            case "png", "jpg", "jpeg", "webp", "gif", "mp3", "ogg", "wav", "mp4", "webm",
                    "ttf", "otf", "so", "pdf", "9.png" -> true;
            default -> false;
        };
    }

    private static final class Raw {
        final String type;
        final String value;
        final String location;

        Raw(String type, String value, String location) {
            this.type = type;
            this.value = value;
            this.location = location;
        }
    }

    private static final class Agg {
        final String type;
        final String value;
        final Set<String> locations = new LinkedHashSet<>();

        Agg(Raw raw) {
            this.type = raw.type;
            this.value = raw.value;
        }
    }
}
