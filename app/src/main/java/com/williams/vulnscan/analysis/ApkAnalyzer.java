package com.williams.vulnscan.analysis;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.content.pm.Signature;
import android.os.Build;

import com.williams.vulnscan.Text;
import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.FirebaseHints;
import com.williams.vulnscan.model.ScanResult;
import com.williams.vulnscan.model.SelectedTarget;
import com.williams.vulnscan.model.Severity;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

public final class ApkAnalyzer {
    /** {@code ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC} (@hide), estável desde a API 23. */
    static final int FLAG_USES_CLEARTEXT_TRAFFIC = 1 << 27;

    public interface Progress {
        void report(String message);
    }

    private final Context context;
    private int shownRisky;
    private int hiddenRisky;
    private int protectedExported;

    public ApkAnalyzer(Context context) {
        this.context = context.getApplicationContext();
    }

    public ScanResult analyze(SelectedTarget target, Progress progress) throws AnalysisException {
        if (target == null || Text.isBlank(target.apkPath)) {
            throw new AnalysisException("Escolha um aplicativo ou um arquivo APK.");
        }
        progress.report("Lendo manifesto e permissões…");
        PackageManager pm = context.getPackageManager();
        boolean installed = target.kind == SelectedTarget.Kind.INSTALLED;
        PackageInfo info = installed
                ? loadInstalled(pm, target.packageName)
                : loadArchive(pm, target.apkPath);
        if (info == null || info.applicationInfo == null) {
            throw new AnalysisException("Não foi possível abrir o APK. O arquivo pode estar corrompido.");
        }
        if (!installed) {
            info.applicationInfo.sourceDir = target.apkPath;
            info.applicationInfo.publicSourceDir = target.apkPath;
        }

        ApplicationInfo app = info.applicationInfo;
        List<Finding> findings = new ArrayList<>();
        String label = resolveLabel(pm, app, target.label, info.packageName);
        addIdentity(info, label, findings);
        boolean requestsInternet = addPermissions(pm, info, installed, findings);
        addFlags(app, findings);
        addComponents(info, findings);

        progress.report("Procurando segredos no pacote…");
        SecretScanner.Result secrets = scanSecrets(app, target.apkPath);
        findings.addAll(secrets.findings);
        if (requestsInternet && hasHighSecret(secrets.findings)) {
            findings.add(new Finding(
                    Severity.ALTO,
                    "Segredo",
                    "Segredo extraível com acesso à rede",
                    "O app pede INTERNET e leva segredo no APK. Quem copiar a chave chama o serviço direto, sem passar pelo aplicativo. Restrinja a chave e mova o segredo para um backend.",
                    "APK",
                    null));
        }
        findings.sort(Comparator
                .comparingInt((Finding finding) -> finding.severity.ordinal())
                .thenComparing(finding -> finding.title == null ? "" : finding.title));

        FirebaseHints hints = secrets.hints == null
                ? new FirebaseHints(null, null, null, null)
                : secrets.hints;
        return new ScanResult(
                label,
                info.packageName,
                info.versionName == null ? "desconhecida" : info.versionName,
                versionCodeOf(info),
                app.minSdkVersion,
                app.targetSdkVersion,
                target.apkPath,
                findings,
                hints,
                System.currentTimeMillis());
    }

    private void addIdentity(PackageInfo info, String label, List<Finding> findings) {
        ApplicationInfo app = info.applicationInfo;
        Severity sdkSeverity = Severity.INFO;
        String sdkNote = "minSdk " + app.minSdkVersion + " · targetSdk " + app.targetSdkVersion
                + " · versão " + (info.versionName == null ? "desconhecida" : info.versionName)
                + " (" + versionCodeOf(info) + ").";
        if (app.targetSdkVersion < 28) {
            sdkSeverity = Severity.MEDIO;
            sdkNote += " targetSdk abaixo de 28 deixa o texto puro liberado por padrão e fica fora de proteções mais novas da plataforma.";
        } else if (app.targetSdkVersion < 33) {
            sdkSeverity = Severity.BAIXO;
            sdkNote += " targetSdk abaixo de 33 não recebe algumas restrições recentes (notificações, armazenamento e exportação explícita).";
        }
        findings.add(new Finding(sdkSeverity, "Manifesto", "Compatibilidade de " + label, sdkNote, info.packageName, null));
        addCertificates(info, findings);
    }

    private boolean addPermissions(PackageManager pm, PackageInfo info, boolean installed, List<Finding> findings) {
        String[] requested = info.requestedPermissions;
        if (requested == null || requested.length == 0) {
            findings.add(new Finding(
                    Severity.INFO,
                    "Permissão",
                    "Nenhuma permissão solicitada",
                    "O manifesto não declara uses-permission.",
                    "AndroidManifest.xml",
                    null));
            return false;
        }
        boolean internet = false;
        List<String> ordinary = new ArrayList<>();
        List<String> custom = new ArrayList<>();
        for (int i = 0; i < requested.length; i++) {
            String name = requested[i];
            if ("android.permission.INTERNET".equals(name)) {
                internet = true;
            }
            int protection = protectionOf(pm, name);
            PermissionCatalog.Assessment assessment = PermissionCatalog.assess(name, protection);
            String state = permissionState(info, i, installed);
            if (assessment != null && assessment.highlight) {
                findings.add(new Finding(
                        assessment.severity,
                        "Permissão",
                        assessment.title,
                        assessment.explanation + " " + state + " Nome completo: " + name + ".",
                        name,
                        null));
            } else if (name.startsWith("android.permission.") || name.startsWith("com.android.")) {
                ordinary.add(PermissionCatalog.shortName(name));
            } else {
                custom.add(name);
            }
        }
        if (!ordinary.isEmpty()) {
            findings.add(new Finding(
                    Severity.INFO,
                    "Permissão",
                    "Outras permissões (" + ordinary.size() + ")",
                    "Permissões comuns ou de nível assinatura, sem o destaque das sensíveis: " + Text.join(", ", ordinary) + ".",
                    "AndroidManifest.xml",
                    null));
        }
        if (!custom.isEmpty()) {
            findings.add(new Finding(
                    Severity.INFO,
                    "Permissão",
                    "Permissões próprias ou de terceiros (" + custom.size() + ")",
                    Text.join(", ", custom),
                    "AndroidManifest.xml",
                    null));
        }
        return internet;
    }

    private static String permissionState(PackageInfo info, int index, boolean installed) {
        if (!installed || info.requestedPermissionsFlags == null || index >= info.requestedPermissionsFlags.length) {
            return "Estado: declarada no manifesto.";
        }
        boolean granted = (info.requestedPermissionsFlags[index] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0;
        return granted ? "Estado: concedida neste aparelho." : "Estado: ainda não concedida neste aparelho.";
    }

    private static int protectionOf(PackageManager pm, String name) {
        try {
            PermissionInfo permission = pm.getPermissionInfo(name, 0);
            return permission.protectionLevel;
        } catch (PackageManager.NameNotFoundException ex) {
            return -1;
        }
    }

    private void addFlags(ApplicationInfo app, List<Finding> findings) {
        boolean debuggable = (app.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        boolean allowBackup = (app.flags & ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;
        boolean cleartext = (app.flags & FLAG_USES_CLEARTEXT_TRAFFIC) != 0;
        boolean testOnly = (app.flags & ApplicationInfo.FLAG_TEST_ONLY) != 0;
        findings.add(new Finding(
                debuggable ? Severity.ALTO : Severity.INFO,
                "Manifesto",
                debuggable ? "android:debuggable ativo" : "android:debuggable desativado",
                debuggable
                        ? "Um depurador pode se conectar ao processo, ler memória e contornar controles. Não publique um APK debug. O tipo release do Gradle desliga essa flag."
                        : "O pacote não aceita depurador. É o esperado em um build de release.",
                "AndroidManifest.xml",
                null));
        findings.add(new Finding(
                allowBackup ? Severity.MEDIO : Severity.INFO,
                "Manifesto",
                allowBackup ? "android:allowBackup ativo" : "android:allowBackup desativado",
                allowBackup
                        ? "O backup pode extrair o diretório privado do app (adb backup em versões antigas e backup na nuvem). Defina android:allowBackup=\"false\" ou exclua dados sensíveis."
                        : "Backup automático desativado. Os dados privados do app ficam de fora do backup.",
                "AndroidManifest.xml",
                null));
        findings.add(new Finding(
                cleartext ? Severity.MEDIO : Severity.INFO,
                "Manifesto",
                cleartext ? "usesCleartextTraffic ativo" : "usesCleartextTraffic desativado",
                cleartext
                        ? "O app pode usar HTTP sem TLS. Numa rede hostil o tráfego pode ser lido ou alterado. Desative o texto puro e use só HTTPS."
                        : "Tráfego em texto puro desativado no manifesto (ou pelo targetSdk). O app deve falar apenas HTTPS.",
                "AndroidManifest.xml",
                null));
        if (testOnly) {
            findings.add(new Finding(
                    Severity.INFO,
                    "Manifesto",
                    "App marcado como testOnly",
                    "O pacote só instala em ambiente de desenvolvimento. Não é um build para distribuir.",
                    "AndroidManifest.xml",
                    null));
        }
    }

    private void addComponents(PackageInfo info, List<Finding> findings) {
        shownRisky = 0;
        hiddenRisky = 0;
        protectedExported = 0;
        considerActivities(info.activities, findings);
        considerServices(info.services, findings);
        considerReceivers(info.receivers, findings);
        considerProviders(info.providers, findings);
        if (hiddenRisky > 0) {
            findings.add(new Finding(
                    Severity.ALTO,
                    "Manifesto",
                    "Outros componentes exportados",
                    "Mais " + hiddenRisky + " componentes exportados sem permissão ficaram de fora da lista. Revise o manifesto e feche o que não precisa ser chamado por outros apps.",
                    "AndroidManifest.xml",
                    null));
        }
        if (protectedExported > 0) {
            findings.add(new Finding(
                    Severity.INFO,
                    "Manifesto",
                    "Componentes exportados com permissão",
                    protectedExported + " componente(s) exportado(s) exigem uma permissão. Continuam sendo ponto de entrada, mas não estão abertos para qualquer app.",
                    "AndroidManifest.xml",
                    null));
        }
    }

    private void considerActivities(ActivityInfo[] items, List<Finding> findings) {
        if (items == null) {
            return;
        }
        for (ActivityInfo component : items) {
            recordExported(
                    component.exported,
                    component.permission,
                    component.name,
                    Severity.MEDIO,
                    "Activity exportada sem permissão",
                    "Esta activity aceita chamadas de outros apps e não exige permissão. A tela inicial normalmente é exportada; as demais podem ser abertas para injetar dados via Intent. Exporte só o necessário e valide todo Intent.",
                    findings);
        }
    }

    private void considerServices(ServiceInfo[] items, List<Finding> findings) {
        if (items == null) {
            return;
        }
        for (ServiceInfo component : items) {
            recordExported(
                    component.exported,
                    component.permission,
                    component.name,
                    Severity.ALTO,
                    "Service exportado sem permissão",
                    "Este service pode ser iniciado ou vinculado por outros aplicativos. Defina android:exported=\"false\" ou exija uma permissão de nível assinatura.",
                    findings);
        }
    }

    private void considerReceivers(ActivityInfo[] items, List<Finding> findings) {
        if (items == null) {
            return;
        }
        for (ActivityInfo component : items) {
            recordExported(
                    component.exported,
                    component.permission,
                    component.name,
                    Severity.ALTO,
                    "Receiver exportado sem permissão",
                    "Este receiver aceita broadcasts de outros apps. Um emissor local pode forjar o Intent. Restrinja com exported=false ou uma permissão.",
                    findings);
        }
    }

    private void recordExported(
            boolean exported,
            String permission,
            String name,
            Severity severity,
            String title,
            String detail,
            List<Finding> findings) {
        if (!exported) {
            return;
        }
        if (!Text.isBlank(permission)) {
            protectedExported++;
            return;
        }
        if (shownRisky >= 40) {
            hiddenRisky++;
            return;
        }
        shownRisky++;
        findings.add(new Finding(severity, "Manifesto", title, detail, name, null));
    }

    private void considerProviders(ProviderInfo[] providers, List<Finding> findings) {
        if (providers == null) {
            return;
        }
        for (ProviderInfo provider : providers) {
            if (!provider.exported) {
                continue;
            }
            boolean readLocked = !Text.isBlank(provider.readPermission);
            boolean writeLocked = !Text.isBlank(provider.writePermission);
            if (readLocked && writeLocked) {
                protectedExported++;
                continue;
            }
            if (shownRisky >= 40) {
                hiddenRisky++;
                continue;
            }
            shownRisky++;
            if (!readLocked && !writeLocked) {
                findings.add(new Finding(
                        Severity.ALTO,
                        "Manifesto",
                        "Provider exportado sem permissão",
                        "Este provider entrega conteúdo a outros apps sem permissão de leitura nem de escrita. Dados guardados nele podem ser lidos ou alterados por qualquer aplicativo do aparelho.",
                        provider.name,
                        null));
            } else {
                String side = readLocked ? "escrita" : "leitura";
                findings.add(new Finding(
                        Severity.MEDIO,
                        "Manifesto",
                        "Provider com " + side + " aberta",
                        "A " + side + " deste provider não exige permissão. Complete a proteção com readPermission e writePermission.",
                        provider.name,
                        null));
            }
        }
    }

    private SecretScanner.Result scanSecrets(ApplicationInfo app, String fallbackPath) throws AnalysisException {
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        if (app.sourceDir != null) {
            paths.add(app.sourceDir);
        }
        if (app.splitSourceDirs != null) {
            Collections.addAll(paths, app.splitSourceDirs);
        }
        if (paths.isEmpty() && fallbackPath != null) {
            paths.add(fallbackPath);
        }
        List<Finding> findings = new ArrayList<>();
        String project = null;
        String apiKey = null;
        String database = null;
        String bucket = null;
        SecretScanner scanner = new SecretScanner();
        boolean any = false;
        try {
            for (String path : paths) {
                File file = new File(path);
                if (!file.isFile()) {
                    continue;
                }
                any = true;
                SecretScanner.Result part = scanner.scan(file);
                findings.addAll(part.findings);
                if (part.hints != null) {
                    if (project == null) {
                        project = part.hints.projectId;
                    }
                    if (apiKey == null) {
                        apiKey = part.hints.apiKey;
                    }
                    if (database == null) {
                        database = part.hints.databaseUrl;
                    }
                    if (bucket == null) {
                        bucket = part.hints.storageBucket;
                    }
                }
            }
        } catch (java.util.zip.ZipException ex) {
            throw new AnalysisException("Não foi possível abrir o APK. O arquivo pode estar corrompido.");
        } catch (java.io.IOException ex) {
            throw new AnalysisException("Falha ao ler o conteúdo do APK.");
        }
        if (!any) {
            throw new AnalysisException("Não foi possível localizar o arquivo APK deste aplicativo.");
        }
        return new SecretScanner.Result(dedupe(findings), new FirebaseHints(project, apiKey, database, bucket));
    }

    static List<Finding> dedupe(List<Finding> findings) {
        List<Finding> merged = new ArrayList<>();
        for (Finding finding : findings) {
            int index = -1;
            for (int i = 0; i < merged.size(); i++) {
                Finding current = merged.get(i);
                if (sameFinding(current, finding)) {
                    index = i;
                    break;
                }
            }
            if (index < 0) {
                merged.add(finding);
            } else {
                Finding current = merged.get(index);
                merged.set(index, current.withLocation(joinLocations(current.location, finding.location)));
            }
        }
        return merged;
    }

    private static boolean sameFinding(Finding left, Finding right) {
        return left.severity == right.severity
                && safe(left.category).equals(safe(right.category))
                && safe(left.title).equals(safe(right.title))
                && safe(left.detail).equals(safe(right.detail))
                && safe(left.sensitiveValue).equals(safe(right.sensitiveValue));
    }

    private static String joinLocations(String left, String right) {
        if (Text.isBlank(left)) {
            return right;
        }
        if (Text.isBlank(right) || left.contains(right)) {
            return left;
        }
        return left + ", " + right;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static boolean hasHighSecret(List<Finding> findings) {
        for (Finding finding : findings) {
            if (finding.severity == Severity.ALTO && "Segredo".equals(finding.category)) {
                return true;
            }
        }
        return false;
    }

    private void addCertificates(PackageInfo info, List<Finding> findings) {
        List<Signature> signatures = signaturesOf(info);
        if (signatures.isEmpty()) {
            findings.add(new Finding(
                    Severity.INFO,
                    "Assinatura",
                    "Certificado não lido",
                    "Não foi possível obter o certificado de assinatura deste pacote.",
                    info.packageName,
                    null));
            return;
        }
        StringBuilder detail = new StringBuilder();
        boolean debugCert = false;
        for (int i = 0; i < signatures.size(); i++) {
            Signature signature = signatures.get(i);
            if (i > 0) {
                detail.append("\n\n");
            }
            String sha = sha256(signature);
            detail.append("SHA-256: ").append(sha == null ? "indisponível" : sha);
            X509Certificate certificate = certificate(signature);
            if (certificate != null) {
                String subject = certificate.getSubjectX500Principal().getName();
                detail.append("\nAssunto: ").append(subject);
                detail.append("\nEmissor: ").append(certificate.getIssuerX500Principal().getName());
                SimpleDateFormat format = new SimpleDateFormat("dd/MM/yyyy", new Locale("pt", "BR"));
                detail.append("\nValidade: ").append(format.format(certificate.getNotBefore()))
                        .append(" até ").append(format.format(certificate.getNotAfter()));
                if (subject.contains("Android Debug")) {
                    debugCert = true;
                }
                if (certificate.getNotAfter().before(new Date())) {
                    detail.append("\nO certificado está vencido.");
                }
            }
        }
        if (Build.VERSION.SDK_INT >= 28 && info.signingInfo != null) {
            if (info.signingInfo.hasMultipleSigners()) {
                detail.append("\nO APK tem mais de um assinante atual.");
            }
            Signature[] history = info.signingInfo.getSigningCertificateHistory();
            if (history != null && history.length > 1) {
                detail.append("\nHá histórico de rotação (").append(history.length).append(" certificados).");
            }
        }
        findings.add(new Finding(
                Severity.INFO,
                "Assinatura",
                signatures.size() == 1 ? "Certificado de assinatura" : "Certificados de assinatura",
                detail.toString(),
                info.packageName,
                null));
        if (debugCert) {
            findings.add(new Finding(
                    Severity.ALTO,
                    "Assinatura",
                    "Assinado com certificado de debug",
                    "O assunto do certificado é Android Debug. Esse certificado é público na SDK. Não distribua um pacote assinado com ele.",
                    info.packageName,
                    null));
        }
    }

    private PackageInfo loadInstalled(PackageManager pm, String packageName) throws AnalysisException {
        if (Text.isBlank(packageName)) {
            throw new AnalysisException("Esse aplicativo não está mais instalado.");
        }
        try {
            return getPackageInfo(pm, packageName, fullFlags());
        } catch (PackageManager.NameNotFoundException ex) {
            throw new AnalysisException("Esse aplicativo não está mais instalado.");
        } catch (RuntimeException first) {
            try {
                return getPackageInfo(pm, packageName, reducedFlags());
            } catch (PackageManager.NameNotFoundException ex) {
                throw new AnalysisException("Esse aplicativo não está mais instalado.");
            } catch (RuntimeException second) {
                try {
                    return getPackageInfo(pm, packageName, minimalFlags());
                } catch (PackageManager.NameNotFoundException ex) {
                    throw new AnalysisException("Esse aplicativo não está mais instalado.");
                } catch (RuntimeException third) {
                    throw new AnalysisException("Não foi possível ler o pacote instalado. Tente o arquivo APK.");
                }
            }
        }
    }

    private PackageInfo loadArchive(PackageManager pm, String path) {
        PackageInfo info = getArchiveInfo(pm, path, fullFlags());
        if (info == null) {
            info = getArchiveInfo(pm, path, minimalFlags());
        }
        return info;
    }

    private static int fullFlags() {
        int flags = PackageManager.GET_PERMISSIONS
                | PackageManager.GET_ACTIVITIES
                | PackageManager.GET_SERVICES
                | PackageManager.GET_RECEIVERS
                | PackageManager.GET_PROVIDERS;
        if (Build.VERSION.SDK_INT >= 28) {
            flags |= PackageManager.GET_SIGNING_CERTIFICATES;
        } else {
            flags |= PackageManager.GET_SIGNATURES;
        }
        return flags;
    }

    private static int reducedFlags() {
        int flags = PackageManager.GET_PERMISSIONS | PackageManager.GET_PROVIDERS | PackageManager.GET_SERVICES;
        if (Build.VERSION.SDK_INT >= 28) {
            flags |= PackageManager.GET_SIGNING_CERTIFICATES;
        } else {
            flags |= PackageManager.GET_SIGNATURES;
        }
        return flags;
    }

    private static int minimalFlags() {
        int flags = PackageManager.GET_PERMISSIONS;
        if (Build.VERSION.SDK_INT >= 28) {
            flags |= PackageManager.GET_SIGNING_CERTIFICATES;
        } else {
            flags |= PackageManager.GET_SIGNATURES;
        }
        return flags;
    }

    private static PackageInfo getPackageInfo(PackageManager pm, String packageName, int flags)
            throws PackageManager.NameNotFoundException {
        if (Build.VERSION.SDK_INT >= 33) {
            return pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags));
        }
        return getPackageInfoLegacy(pm, packageName, flags);
    }

    @SuppressWarnings("deprecation")
    private static PackageInfo getPackageInfoLegacy(PackageManager pm, String packageName, int flags)
            throws PackageManager.NameNotFoundException {
        return pm.getPackageInfo(packageName, flags);
    }

    private static PackageInfo getArchiveInfo(PackageManager pm, String path, int flags) {
        if (Build.VERSION.SDK_INT >= 33) {
            return pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(flags));
        }
        return getArchiveInfoLegacy(pm, path, flags);
    }

    @SuppressWarnings("deprecation")
    private static PackageInfo getArchiveInfoLegacy(PackageManager pm, String path, int flags) {
        return pm.getPackageArchiveInfo(path, flags);
    }

    private static List<Signature> signaturesOf(PackageInfo info) {
        if (Build.VERSION.SDK_INT >= 28 && info.signingInfo != null) {
            Signature[] current = info.signingInfo.getApkContentsSigners();
            if (current != null && current.length > 0) {
                return Arrays.asList(current);
            }
        }
        return legacySignatures(info);
    }

    @SuppressWarnings("deprecation")
    private static List<Signature> legacySignatures(PackageInfo info) {
        if (info.signatures != null && info.signatures.length > 0) {
            return Arrays.asList(info.signatures);
        }
        return Collections.emptyList();
    }

    static String sha256(Signature signature) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray());
            StringBuilder builder = new StringBuilder(hash.length * 3);
            for (int i = 0; i < hash.length; i++) {
                if (i > 0) {
                    builder.append(':');
                }
                builder.append(String.format(Locale.US, "%02X", hash[i]));
            }
            return builder.toString();
        } catch (Exception ex) {
            return null;
        }
    }

    private static X509Certificate certificate(Signature signature) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(signature.toByteArray()));
        } catch (CertificateException ex) {
            return null;
        }
    }

    @SuppressWarnings("deprecation")
    private static long versionCodeOf(PackageInfo info) {
        if (Build.VERSION.SDK_INT >= 28) {
            return info.getLongVersionCode();
        }
        return info.versionCode;
    }

    private static String resolveLabel(PackageManager pm, ApplicationInfo app, String fallback, String packageName) {
        try {
            CharSequence label = app.loadLabel(pm);
            if (label != null && label.length() > 0) {
                return label.toString();
            }
        } catch (RuntimeException ignored) {
            // O nome do arquivo ainda serve como rótulo.
        }
        if (!Text.isBlank(fallback)) {
            return fallback;
        }
        return packageName;
    }
}
