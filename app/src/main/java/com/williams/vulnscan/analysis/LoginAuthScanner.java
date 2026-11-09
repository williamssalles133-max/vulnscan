package com.williams.vulnscan.analysis;

import com.williams.vulnscan.Text;
import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.Severity;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
 * Diagnóstico de login no APK. Não testa senhas, não tenta autenticar e não indica como contornar a tela.
 */
public final class LoginAuthScanner {
    private static final int MAX_ENTRY_BYTES = 32 * 1024 * 1024;
    private static final int MIN_STRING = 8;

    private static final Pattern PASSWORD_EQUALS = Pattern.compile(
            "(?i)(?:password|senha|passwd)\\s*(?:==|\\.equals(?:IgnoreCase)?\\s*\\()\\s*[\"']([^\"']{4,64})[\"']");
    private static final Pattern REVERSE_EQUALS = Pattern.compile(
            "(?i)[\"']([^\"']{4,64})[\"']\\s*\\.equals(?:IgnoreCase)?\\s*\\(\\s*(?:password|senha|passwd)\\s*\\)");
    private static final Pattern ASSIGNED_SECRET = Pattern.compile(
            "(?i)(?:password|senha|passwd|user_?password|default_?password)\\s*[=:]\\s*[\"']([^\"'\\s]{4,64})[\"']");
    private static final Pattern USER_AND_PASSWORD = Pattern.compile(
            "(?i)(?:user(?:name)?|usuario|login)\\s*[=:]\\s*[\"']([^\"']{2,40})[\"'][^\\n]{0,80}(?:password|senha|passwd)\\s*[=:]\\s*[\"']([^\"']{4,64})[\"']");
    private static final Pattern BASIC_AUTH = Pattern.compile(
            "(?i)\\bBasic\\s+[A-Za-z0-9+/]{12,}={0,2}");
    private static final Pattern URL_USERINFO = Pattern.compile(
            "https?://([^/\\s:@]{2,40}):([^/\\s@]{4,64})@");
    private static final Pattern WEAK_HASH_NEAR = Pattern.compile(
            "(?i)(password|senha|passwd).{0,80}(md5|sha-?1)|(md5|sha-?1).{0,80}(password|senha|passwd)");
    private static final Pattern LOCAL_EQUALS = Pattern.compile(
            "(?i)(?:password|senha|passwd)\\s*\\.equals(?:IgnoreCase)?\\s*\\(|\\.equals(?:IgnoreCase)?\\s*\\(\\s*(?:password|senha|passwd)\\s*\\)");
    private static final Pattern PREF_SECRET = Pattern.compile(
            "(?i)(?:putString|getString)\\s*\\(\\s*[\"'][^\"']{0,40}(password|senha|passwd|token|auth)[^\"']{0,20}[\"']");
    private static final Pattern LOG_SECRET = Pattern.compile(
            "(?i)Log\\.[divwe]\\s*\\([^)]{0,120}(password|senha|passwd|token)");
    private static final Pattern HTTP_URL = Pattern.compile(
            "http://[a-zA-Z0-9._~:/?#\\[\\]@!$&'()*+,;=%\\-]{6,160}");
    private static final Pattern DIGEST_MD5 = Pattern.compile("(?i)getInstance\\s*\\(\\s*[\"']MD5[\"']\\s*\\)");
    private static final Pattern DIGEST_SHA1 = Pattern.compile("(?i)getInstance\\s*\\(\\s*[\"']SHA-?1[\"']\\s*\\)");

    private final List<Finding> findings = new ArrayList<>();
    private final Map<String, Set<String>> locations = new LinkedHashMap<>();
    private boolean sawLogin;
    private boolean sawRateLimit;
    private boolean sawFirebase;
    private boolean sawStrongHash;
    private boolean sawNetworkSecurityConfig;
    private boolean sawHttpLogin;
    private boolean sawWeakHashSameString;
    private boolean sawWeakHashSameFile;
    private boolean sawLocalEquals;
    private boolean manifestCleartext;
    private boolean manifestRead;

    public List<Finding> scan(File apk, boolean manifestRead, boolean cleartextTraffic) throws IOException {
        findings.clear();
        locations.clear();
        sawLogin = false;
        sawRateLimit = false;
        sawFirebase = false;
        sawStrongHash = false;
        sawNetworkSecurityConfig = false;
        sawHttpLogin = false;
        sawWeakHashSameString = false;
        sawWeakHashSameFile = false;
        sawLocalEquals = false;
        this.manifestRead = manifestRead;
        this.manifestCleartext = cleartextTraffic;

        try (ZipFile zip = new ZipFile(apk)) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !shouldScan(entry.getName()) || entry.getSize() > MAX_ENTRY_BYTES) {
                    continue;
                }
                byte[] data;
                try (InputStream in = zip.getInputStream(entry)) {
                    data = readCapped(in, MAX_ENTRY_BYTES);
                } catch (IOException ignored) {
                    continue;
                }
                if (data == null) {
                    continue;
                }
                scanEntry(data, entry.getName());
            }
        }
        addAdvisories(apk.getName());
        return new ArrayList<>(findings);
    }

    private void scanEntry(byte[] data, String name) {
        FileSignals signals = new FileSignals();
        List<String> strings = new ArrayList<>();
        walkAscii(data, strings::add);
        if (wantsUtf16(name)) {
            walkUtf16(data, 0, strings::add);
            walkUtf16(data, 1, strings::add);
        }
        for (String value : strings) {
            if (value.length() < MIN_STRING) {
                continue;
            }
            inspect(value, name, signals);
        }
        if (!signals.encryptedPrefs) {
            for (Hit hit : signals.prefHits) {
                add(hit.severity, hit.title, hit.detail, hit.location, hit.secret);
            }
        }
        if (signals.sawPasswordWord && (signals.sawMd5 || signals.sawSha1) && !signals.sawWeakSameString) {
            sawWeakHashSameFile = true;
            add(Severity.MEDIO,
                    "Possível hash fraco perto de senha",
                    "O mesmo arquivo cita senha e MD5 ou SHA-1, mas não necessariamente juntos. MD5 e SHA-1 são rápidos demais para senha. Se a senha passa por esse hash, troque por bcrypt, scrypt ou Argon2 no servidor. Isto é uma heurística, não uma prova.",
                    name,
                    null);
        }
    }

    private void inspect(String text, String location, FileSignals signals) {
        String lower = text.toLowerCase(Locale.US);
        if (containsLoginWord(lower)) {
            sawLogin = true;
            signals.sawPasswordWord = signals.sawPasswordWord || lower.contains("password") || lower.contains("senha") || lower.contains("passwd");
        }
        if (lower.contains("ratelimit") || lower.contains("rate_limit") || lower.contains("rate-limit")
                || lower.contains("lockout") || lower.contains("maxattempts") || lower.contains("max_attempts")
                || lower.contains("too many attempts") || lower.contains("tentativas")
                || lower.contains("loginattempts") || lower.contains("attemptcount")) {
            sawRateLimit = true;
        }
        if (lower.contains("firebaseauth") || lower.contains("firebase.auth")
                || lower.contains("signinwithemailandpassword") || lower.contains("firebaseio")
                || lower.contains("firebaseapp")) {
            sawFirebase = true;
        }
        if (lower.contains("bcrypt") || lower.contains("scrypt") || lower.contains("argon2") || lower.contains("pbkdf2")) {
            sawStrongHash = true;
        }
        if (lower.contains("networksecurityconfig") || lower.contains("network_security_config")) {
            sawNetworkSecurityConfig = true;
        }
        if (lower.contains("encryptedsharedpreferences") || lower.contains("androidx.security.crypto")) {
            signals.encryptedPrefs = true;
        }
        if (DIGEST_MD5.matcher(text).find()) {
            signals.sawMd5 = true;
        }
        if (DIGEST_SHA1.matcher(text).find()) {
            signals.sawSha1 = true;
        }
        if (WEAK_HASH_NEAR.matcher(text).find()) {
            signals.sawWeakSameString = true;
            sawWeakHashSameString = true;
            add(Severity.ALTO,
                    "Senha associada a MD5 ou SHA-1",
                    "O texto junta senha com MD5 ou SHA-1. Esses algoritmos são rápidos e inadequados para senha. Calcule um hash lento (bcrypt, scrypt ou Argon2) só no servidor, com sal único por usuário.",
                    location,
                    null);
        }

        if (PASSWORD_EQUALS.matcher(text).find()
                || REVERSE_EQUALS.matcher(text).find()
                || LOCAL_EQUALS.matcher(text).find()) {
            sawLocalEquals = true;
        }
        collectGroup(PASSWORD_EQUALS, text, location, Severity.ALTO,
                "Senha comparada com valor fixo",
                "O código compara a senha com um texto fixo dentro do APK. Quem descompila o pacote lê esse valor. Apague a comparação e valide a senha apenas no servidor.");
        collectGroup(REVERSE_EQUALS, text, location, Severity.ALTO,
                "Senha comparada com valor fixo",
                "O código compara a senha com um texto fixo dentro do APK. Quem descompila o pacote lê esse valor. Apague a comparação e valide a senha apenas no servidor.");
        if (!USER_AND_PASSWORD.matcher(text).find()) {
            collectGroup(ASSIGNED_SECRET, text, location, Severity.ALTO,
                    "Senha ou usuário padrão no pacote",
                    "Há uma atribuição de senha no APK. Credencial embutida não é segredo. Remova o valor, rotacione se ele já foi publicado e autentique no servidor.");
        }
        collectUserPassword(text, location);
        collectBasic(text, location);
        collectUserInfo(text, location);
        collectHttp(text, location);
        if (PREF_SECRET.matcher(text).find()) {
            signals.prefHits.add(new Hit(
                    Severity.ALTO,
                    "Senha ou token em SharedPreferences",
                    "Uma chave de preferência parece guardar senha ou token. SharedPreferences comum é um arquivo XML legível em aparelho com backup ou acesso local. Use EncryptedSharedPreferences ou o Keystore só para o token de sessão, e nunca grave a senha.",
                    location,
                    null));
        }
        if (LOG_SECRET.matcher(text).find()) {
            add(Severity.MEDIO,
                    "Senha ou token em log",
                    "Um log cita senha ou token. Logs vazam em logcat e em relatórios de crash. Remova o valor do log e registre só um identificador opaco.",
                    location,
                    null);
        }
    }

    private void collectGroup(Pattern pattern, String text, String location, Severity severity, String title, String detail) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            String secret = matcher.group(1);
            if (placeholder(secret)) {
                continue;
            }
            add(severity, title, detail, location, secret);
        }
    }

    private void collectUserPassword(String text, String location) {
        Matcher matcher = USER_AND_PASSWORD.matcher(text);
        while (matcher.find()) {
            String user = matcher.group(1);
            String secret = matcher.group(2);
            if (placeholder(user) && placeholder(secret)) {
                continue;
            }
            if (placeholder(secret)) {
                continue;
            }
            add(Severity.ALTO,
                    "Par usuário e senha embutido",
                    "O pacote traz usuário e senha no mesmo texto. Isso é credencial padrão recuperável. Apague os dois valores e crie a conta só no servidor.",
                    location,
                    user + " / " + secret);
        }
    }

    private void collectBasic(String text, String location) {
        Matcher matcher = BASIC_AUTH.matcher(text);
        while (matcher.find()) {
            add(Severity.ALTO,
                    "Autenticação Basic embutida",
                    "Há um cabeçalho Authorization Basic no pacote. O valor é só Base64 do par usuário:senha, então não esconde a credencial. Remova o cabeçalho e use um token obtido no servidor por HTTPS.",
                    location,
                    matcher.group());
        }
    }

    private void collectUserInfo(String text, String location) {
        Matcher matcher = URL_USERINFO.matcher(text);
        while (matcher.find()) {
            String secret = matcher.group(2);
            if (placeholder(secret)) {
                continue;
            }
            add(Severity.ALTO,
                    "Senha na URL",
                    "Uma URL traz usuário e senha antes do host. Ela vaza em log, proxy e no próprio APK. Tire a senha da URL e autentique com um token.",
                    location,
                    secret);
        }
    }

    private void collectHttp(String text, String location) {
        Matcher matcher = HTTP_URL.matcher(text);
        while (matcher.find()) {
            String url = matcher.group();
            String lower = url.toLowerCase(Locale.US);
            if (!(lower.contains("login") || lower.contains("signin") || lower.contains("sign-in")
                    || lower.contains("auth") || lower.contains("oauth") || lower.contains("password")
                    || lower.contains("senha") || lower.contains("token") || lower.contains("session")
                    || lower.contains("account") || lower.contains("usuario"))) {
                continue;
            }
            sawHttpLogin = true;
            sawLogin = true;
            add(Severity.ALTO,
                    "Login por HTTP sem TLS",
                    "Encontramos um endereço http:// ligado a login ou sessão. A senha pode ser lida na rede. Troque por HTTPS e recuse texto puro.",
                    location,
                    url);
        }
    }

    private void addAdvisories(String apkName) {
        if (sawLocalEquals) {
            add(Severity.ALTO,
                    "Senha conferida no próprio aparelho",
                    "O código compara a senha dentro do app, em vez de perguntar a um servidor. Quem descompila o APK entende essa decisão e a credencial, se estiver no cliente, deixa de ser segredo. Mova a verificação para o servidor, com hash lento, e devolva um token de sessão. Esta análise não mostra como pular a tela.",
                    apkName,
                    null);
        }
        if (sawLogin && !sawRateLimit) {
            add(Severity.INFO,
                    "Sem indício de limite de tentativas",
                    "Recomendação, não é uma conclusão. O APK não cita bloqueio, limite de tentativas ou rate limit. A ausência desse texto não prova que o servidor aceita tentativas infinitas, nem o contrário. Confirme no backend um limite com bloqueio temporário. Esta verificação não envia senhas.",
                    apkName,
                    null);
        } else if (sawLogin) {
            add(Severity.INFO,
                    "Texto sugere limite de tentativas",
                    "Recomendação. O pacote cita algo como bloqueio ou contagem de tentativas. Isso não prova que o servidor corta a tentativa. Confirme a regra no backend e mantenha o limite fora do cliente.",
                    apkName,
                    null);
        }
        if (manifestRead && manifestCleartext) {
            add(Severity.MEDIO,
                    "Login pode usar texto puro",
                    "usesCleartextTraffic está ativo. Um login por HTTP fica exposto na rede. Desative a flag, use só HTTPS e fixe o domínio numa network security config.",
                    "AndroidManifest.xml",
                    null);
        } else if (manifestRead && sawLogin) {
            add(Severity.INFO,
                    "usesCleartextTraffic desativado",
                    "O manifesto não libera texto puro. Mantenha o login apenas em HTTPS.",
                    "AndroidManifest.xml",
                    null);
        }
        if (sawLogin && !sawNetworkSecurityConfig) {
            add(Severity.BAIXO,
                    "Sem network security config visível",
                    "Recomendação. Não achamos networkSecurityConfig no pacote. Uma config de rede ajuda a recusar HTTP e a fixar os domínios de login. A ausência do nome no APK não prova que o servidor esteja aberto.",
                    apkName,
                    null);
        }
        if (sawWeakHashSameFile && !sawWeakHashSameString) {
            // O achado por arquivo já foi emitido durante a varredura.
        }
        if (sawStrongHash) {
            add(Severity.INFO,
                    "Há referência a hash lento",
                    "O pacote cita bcrypt, scrypt, Argon2 ou PBKDF2. Confirme que a senha não é comparada em texto puro no cliente e que o hash fica só no servidor.",
                    apkName,
                    null);
        }
        if (sawFirebase) {
            add(Severity.INFO,
                    "Firebase Auth no cliente",
                    "O app parece usar Firebase. A API key do cliente não é segredo e não protege os dados. Feche as regras do Firestore, Realtime Database e Storage, exija usuário autenticado e ative o App Check. Não guarde a senha no aparelho.",
                    apkName,
                    null);
        }
        if (!sawLogin && !sawHttpLogin && findings.isEmpty()) {
            add(Severity.INFO,
                    "Nenhum fluxo de login evidente",
                    "Não achamos texto claro de senha, login ou sessão. O app pode autenticar de um jeito ofuscado, ou simplesmente não ter login. Isso não é um atestado de segurança.",
                    apkName,
                    null);
        }
    }

    private void add(Severity severity, String title, String detail, String location, String secret) {
        String key = severity.name() + "|" + title + "|" + (secret == null ? "" : secret);
        Set<String> where = locations.computeIfAbsent(key, ignored -> new LinkedHashSet<>());
        if (where.size() >= 6) {
            return;
        }
        boolean first = where.isEmpty();
        where.add(location);
        if (!first) {
            for (int i = 0; i < findings.size(); i++) {
                Finding current = findings.get(i);
                if (current.severity == severity && title.equals(current.title) && secretsEqual(secret, current.sensitiveValue)) {
                    findings.set(i, current.withLocation(Text.join(", ", new ArrayList<>(where))));
                    return;
                }
            }
        }
        findings.add(new Finding(severity, "Login", title, detail, location, secret));
    }

    private static boolean secretsEqual(String left, String right) {
        if (left == null) {
            return right == null;
        }
        return left.equals(right);
    }

    private static boolean containsLoginWord(String lower) {
        return lower.contains("password") || lower.contains("senha") || lower.contains("passwd")
                || lower.contains("login") || lower.contains("signin") || lower.contains("sign-in")
                || lower.contains("authenticate");
    }

    private static boolean placeholder(String value) {
        if (value == null) {
            return true;
        }
        String lower = value.trim().toLowerCase(Locale.US);
        if (lower.length() < 4) {
            return true;
        }
        return lower.equals("password") || lower.equals("senha") || lower.equals("secret")
                || lower.equals("changeme") || lower.equals("example") || lower.equals("placeholder")
                || lower.equals("todo") || lower.equals("null") || lower.equals("undefined")
                || lower.contains("your_password") || lower.contains("your-password")
                || lower.contains("placeholder") || lower.contains("%s") || lower.contains("${")
                || lower.contains("****");
    }

    static boolean shouldScan(String name) {
        String lower = name.toLowerCase(Locale.US);
        if (lower.contains("..") || lower.startsWith("lib/") || lower.startsWith("meta-inf/") || lower.startsWith("kotlin/")) {
            return false;
        }
        String ext = extension(lower);
        if (ext.equals("png") || ext.equals("jpg") || ext.equals("jpeg") || ext.equals("webp")
                || ext.equals("gif") || ext.equals("mp3") || ext.equals("so") || ext.equals("ttf")) {
            return false;
        }
        return lower.equals("androidmanifest.xml")
                || lower.equals("resources.arsc")
                || (lower.startsWith("classes") && lower.endsWith(".dex"))
                || lower.startsWith("res/")
                || lower.startsWith("assets/");
    }

    private static boolean wantsUtf16(String name) {
        String lower = name.toLowerCase(Locale.US);
        return lower.endsWith(".xml") || lower.equals("androidmanifest.xml") || lower.equals("resources.arsc");
    }

    private static String extension(String name) {
        int slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        int dot = name.lastIndexOf('.');
        if (dot <= slash) {
            return "";
        }
        return name.substring(dot + 1);
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
                if (i - start >= MIN_STRING && i - start <= 100_000) {
                    sink.accept(new String(data, start, i - start, StandardCharsets.ISO_8859_1));
                }
                start = -1;
            }
        }
    }

    private static void walkUtf16(byte[] data, int align, Sink sink) {
        StringBuilder builder = new StringBuilder();
        for (int i = align; i + 1 < data.length; i += 2) {
            char c = (char) ((data[i] & 0xff) | ((data[i + 1] & 0xff) << 8));
            if (c >= 32 && c < 127) {
                if (builder.length() < 100_000) {
                    builder.append(c);
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

    private static final class FileSignals {
        boolean sawPasswordWord;
        boolean sawMd5;
        boolean sawSha1;
        boolean sawWeakSameString;
        boolean encryptedPrefs;
        final List<Hit> prefHits = new ArrayList<>();
    }

    private static final class Hit {
        final Severity severity;
        final String title;
        final String detail;
        final String location;
        final String secret;

        Hit(Severity severity, String title, String detail, String location, String secret) {
            this.severity = severity;
            this.title = title;
            this.detail = detail;
            this.location = location;
            this.secret = secret;
        }
    }
}
