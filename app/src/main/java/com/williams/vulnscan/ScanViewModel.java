package com.williams.vulnscan;

import android.app.Application;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.williams.vulnscan.ai.AiClient;
import com.williams.vulnscan.ai.CodeContextSummarizer;
import com.williams.vulnscan.ai.FindingSummarizer;
import com.williams.vulnscan.analysis.AnalysisException;
import com.williams.vulnscan.analysis.ApkAnalyzer;
import com.williams.vulnscan.analysis.ApkCodeContext;
import com.williams.vulnscan.analysis.ApkContextExtractor;
import com.williams.vulnscan.analysis.LoginAuthScanner;
import com.williams.vulnscan.analysis.LoginManifestReader;
import com.williams.vulnscan.data.Event;
import com.williams.vulnscan.data.SecurePrefs;
import com.williams.vulnscan.firebase.FirebaseRulesTester;
import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.FirebaseHints;
import com.williams.vulnscan.model.ProbeResult;
import com.williams.vulnscan.model.ScanResult;
import com.williams.vulnscan.model.SelectedTarget;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public class ScanViewModel extends AndroidViewModel {
    private static final long MAX_APK_BYTES = 400L * 1024L * 1024L;

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private final AtomicInteger analysisToken = new AtomicInteger();
    private SecurePrefs securePrefs;

    private final MutableLiveData<SelectedTarget> selected = new MutableLiveData<>();
    private final MutableLiveData<ScanResult> scan = new MutableLiveData<>();
    private final MutableLiveData<Boolean> analysisRunning = new MutableLiveData<>(false);
    private final MutableLiveData<String> analysisStatus = new MutableLiveData<>();
    private final MutableLiveData<Event<String>> analysisError = new MutableLiveData<>();

    private final MutableLiveData<List<Finding>> loginFindings = new MutableLiveData<>();
    private final MutableLiveData<Boolean> loginRunning = new MutableLiveData<>(false);
    private final MutableLiveData<String> loginStatus = new MutableLiveData<>();
    private final MutableLiveData<Event<String>> loginError = new MutableLiveData<>();

    private final MutableLiveData<List<ProbeResult>> probes = new MutableLiveData<>();
    private final MutableLiveData<Boolean> probeRunning = new MutableLiveData<>(false);
    private final MutableLiveData<Event<String>> firebaseError = new MutableLiveData<>();

    private final MutableLiveData<Boolean> keyAvailable = new MutableLiveData<>(false);
    private final MutableLiveData<Boolean> keyPresent = new MutableLiveData<>(false);
    private final MutableLiveData<String> keyMessage = new MutableLiveData<>();
    private final MutableLiveData<Boolean> aiRunning = new MutableLiveData<>(false);
    private final MutableLiveData<String> aiStatus = new MutableLiveData<>();
    private final MutableLiveData<String> aiTitle = new MutableLiveData<>();
    private final MutableLiveData<String> aiText = new MutableLiveData<>();
    private final MutableLiveData<Event<String>> aiError = new MutableLiveData<>();

    public ScanViewModel(@NonNull Application application) {
        super(application);
        refreshKey();
    }

    public LiveData<SelectedTarget> selected() {
        return selected;
    }

    public LiveData<ScanResult> scan() {
        return scan;
    }

    public LiveData<Boolean> analysisRunning() {
        return analysisRunning;
    }

    public LiveData<String> analysisStatus() {
        return analysisStatus;
    }

    public LiveData<Event<String>> analysisError() {
        return analysisError;
    }

    public LiveData<List<Finding>> loginFindings() {
        return loginFindings;
    }

    public LiveData<Boolean> loginRunning() {
        return loginRunning;
    }

    public LiveData<String> loginStatus() {
        return loginStatus;
    }

    public LiveData<Event<String>> loginError() {
        return loginError;
    }

    public LiveData<List<ProbeResult>> probes() {
        return probes;
    }

    public LiveData<Boolean> probeRunning() {
        return probeRunning;
    }

    public LiveData<Event<String>> firebaseError() {
        return firebaseError;
    }

    public LiveData<Boolean> keyAvailable() {
        return keyAvailable;
    }

    public LiveData<Boolean> keyPresent() {
        return keyPresent;
    }

    public LiveData<String> keyMessage() {
        return keyMessage;
    }

    public LiveData<Boolean> aiRunning() {
        return aiRunning;
    }

    public LiveData<String> aiStatus() {
        return aiStatus;
    }

    public LiveData<String> aiTitle() {
        return aiTitle;
    }

    public LiveData<String> aiText() {
        return aiText;
    }

    public LiveData<Event<String>> aiError() {
        return aiError;
    }

    public void selectInstalled(String packageName) {
        try {
            PackageManager pm = getApplication().getPackageManager();
            ApplicationInfo info = pm.getApplicationInfo(packageName, 0);
            CharSequence label = pm.getApplicationLabel(info);
            String name = label == null || label.length() == 0 ? packageName : label.toString();
            selected.setValue(SelectedTarget.installed(packageName, name, info.sourceDir));
        } catch (Exception ex) {
            analysisError.setValue(new Event<>(s(R.string.err_open_app)));
        }
    }

    public void importApk(Uri uri) {
        if (uri == null || Boolean.TRUE.equals(analysisRunning.getValue())) {
            return;
        }
        analysisRunning.setValue(true);
        analysisStatus.setValue(s(R.string.status_copying));
        io.execute(() -> {
            File dest = new File(getApplication().getCacheDir(), "alvo.apk");
            try (InputStream in = getApplication().getContentResolver().openInputStream(uri)) {
                if (in == null) {
                    throw new IllegalStateException("empty");
                }
                try (OutputStream out = new FileOutputStream(dest)) {
                    byte[] buffer = new byte[16384];
                    long total = 0;
                    int read;
                    while ((read = in.read(buffer)) >= 0) {
                        total += read;
                        if (total > MAX_APK_BYTES) {
                            dest.delete();
                            analysisError.postValue(new Event<>(s(R.string.err_apk_too_big)));
                            return;
                        }
                        out.write(buffer, 0, read);
                    }
                }
                String name = displayName(uri);
                if (name == null) {
                    name = "arquivo.apk";
                }
                selected.postValue(SelectedTarget.file(dest.getAbsolutePath(), name));
                analysisStatus.postValue(null);
            } catch (Exception ex) {
                dest.delete();
                analysisError.postValue(new Event<>(s(R.string.err_pick_apk)));
            } finally {
                analysisRunning.postValue(false);
            }
        });
    }

    public void analyze() {
        SelectedTarget target = selected.getValue();
        if (target == null) {
            analysisError.setValue(new Event<>(s(R.string.err_no_target)));
            return;
        }
        if (Boolean.TRUE.equals(analysisRunning.getValue())) {
            return;
        }
        int token = analysisToken.incrementAndGet();
        analysisRunning.setValue(true);
        analysisStatus.setValue(s(R.string.status_manifest));
        io.execute(() -> {
            try {
                ScanResult result = new ApkAnalyzer(getApplication()).analyze(target, message -> {
                    if (token == analysisToken.get()) {
                        analysisStatus.postValue(message);
                    }
                });
                if (token != analysisToken.get()) {
                    return;
                }
                scan.postValue(result);
                analysisStatus.postValue(s(R.string.status_done, result.findings.size()));
            } catch (AnalysisException ex) {
                if (token == analysisToken.get()) {
                    analysisStatus.postValue(null);
                    analysisError.postValue(new Event<>(ex.getMessage()));
                }
            } catch (OutOfMemoryError ex) {
                if (token == analysisToken.get()) {
                    analysisStatus.postValue(null);
                    analysisError.postValue(new Event<>(s(R.string.err_oom)));
                }
            } catch (Exception ex) {
                if (token == analysisToken.get()) {
                    analysisStatus.postValue(null);
                    analysisError.postValue(new Event<>(s(R.string.err_analysis)));
                }
            } finally {
                if (token == analysisToken.get()) {
                    analysisRunning.postValue(false);
                }
            }
        });
    }

    public void analyzeLogin() {
        SelectedTarget target = selected.getValue();
        if (target == null) {
            loginError.setValue(new Event<>(s(R.string.login_no_target)));
            return;
        }
        if (Boolean.TRUE.equals(loginRunning.getValue())) {
            return;
        }
        loginRunning.setValue(true);
        loginStatus.setValue(s(R.string.status_login));
        io.execute(() -> {
            try {
                LoginManifestReader.Flags flags = LoginManifestReader.read(getApplication(), target);
                List<File> apks = apkFiles(target);
                if (apks.isEmpty()) {
                    loginError.postValue(new Event<>(s(R.string.err_apk_read)));
                    loginStatus.postValue(null);
                    return;
                }
                LoginAuthScanner scanner = new LoginAuthScanner();
                List<Finding> merged = new ArrayList<>();
                for (File apk : apks) {
                    merged.addAll(scanner.scan(apk, flags.read, flags.cleartext));
                }
                loginFindings.postValue(merged);
                loginStatus.postValue(s(R.string.status_login_done, merged.size()));
            } catch (java.util.zip.ZipException ex) {
                loginStatus.postValue(null);
                loginError.postValue(new Event<>(s(R.string.err_apk_corrupt)));
            } catch (OutOfMemoryError ex) {
                loginStatus.postValue(null);
                loginError.postValue(new Event<>(s(R.string.err_oom)));
            } catch (Exception ex) {
                loginStatus.postValue(null);
                loginError.postValue(new Event<>(s(R.string.err_analysis)));
            } finally {
                loginRunning.postValue(false);
            }
        });
    }

    public void probe(FirebaseHints hints) {
        if (Boolean.TRUE.equals(probeRunning.getValue())) {
            return;
        }
        probeRunning.setValue(true);
        io.execute(() -> {
            try {
                List<ProbeResult> results = new FirebaseRulesTester().test(hints);
                probes.postValue(results);
            } catch (Exception ex) {
                firebaseError.postValue(new Event<>(s(R.string.err_network)));
            } finally {
                probeRunning.postValue(false);
            }
        });
    }

    public void refreshKey() {
        io.execute(() -> {
            try {
                SecurePrefs prefs = prefs();
                keyAvailable.postValue(true);
                keyPresent.postValue(prefs.getApiKey() != null);
                keyMessage.postValue(prefs.getApiKey() != null ? s(R.string.key_saved) : s(R.string.key_missing));
            } catch (Exception ex) {
                keyAvailable.postValue(false);
                keyPresent.postValue(false);
                keyMessage.postValue(s(R.string.key_unavailable));
            }
        });
    }

    public void saveKey(String raw) {
        String value = Text.trimToNull(raw);
        if (value == null) {
            aiError.setValue(new Event<>(s(R.string.key_empty)));
            return;
        }
        io.execute(() -> {
            try {
                prefs().setApiKey(value);
                keyAvailable.postValue(true);
                keyPresent.postValue(true);
                keyMessage.postValue(s(R.string.key_stored));
            } catch (Exception ex) {
                keyAvailable.postValue(false);
                aiError.postValue(new Event<>(s(R.string.key_save_failed)));
            }
        });
    }

    public void clearKey() {
        io.execute(() -> {
            try {
                SecurePrefs prefs = prefs();
                prefs.clear();
                keyAvailable.postValue(true);
                keyPresent.postValue(false);
                keyMessage.postValue(s(R.string.key_removed));
            } catch (Exception ex) {
                aiError.postValue(new Event<>(s(R.string.key_unavailable)));
            }
        });
    }

    public void analyzeWithAi(String typedKey) {
        ScanResult currentScan = scan.getValue();
        List<ProbeResult> currentProbes = probes.getValue();
        List<Finding> currentLogin = loginFindings.getValue();
        boolean hasScan = currentScan != null && currentScan.findings != null && !currentScan.findings.isEmpty();
        boolean hasProbes = currentProbes != null && !currentProbes.isEmpty();
        boolean hasLogin = currentLogin != null && !currentLogin.isEmpty();
        if (!hasScan && !hasProbes && !hasLogin) {
            aiError.setValue(new Event<>(s(R.string.ai_need_data)));
            return;
        }
        if (Boolean.TRUE.equals(aiRunning.getValue())) {
            return;
        }
        aiRunning.setValue(true);
        aiTitle.setValue(s(R.string.ai_title_summary));
        aiStatus.setValue(s(R.string.status_ai));
        String summary = FindingSummarizer.summarize(currentScan, currentProbes, currentLogin);
        io.execute(() -> {
            try {
                String key = resolveKey(typedKey);
                if (key == null) {
                    return;
                }
                String answer = new AiClient().analyze(key, summary);
                aiText.postValue(answer);
            } catch (AiClient.AiException ex) {
                aiError.postValue(new Event<>(ex.getMessage()));
            } catch (UnknownHostException ex) {
                aiError.postValue(new Event<>(s(R.string.err_no_network)));
            } catch (SocketTimeoutException ex) {
                aiError.postValue(new Event<>(s(R.string.err_timeout)));
            } catch (Exception ex) {
                aiError.postValue(new Event<>(s(R.string.err_network)));
            } finally {
                aiRunning.postValue(false);
                aiStatus.postValue(null);
            }
        });
    }

    public void analyzeDeep(String typedKey) {
        SelectedTarget target = selected.getValue();
        if (target == null || Text.isBlank(target.apkPath)) {
            aiError.setValue(new Event<>(s(R.string.deep_no_target)));
            return;
        }
        if (Boolean.TRUE.equals(aiRunning.getValue())) {
            return;
        }
        if (Boolean.TRUE.equals(analysisRunning.getValue())) {
            aiError.setValue(new Event<>(s(R.string.deep_busy)));
            return;
        }
        aiRunning.setValue(true);
        aiTitle.setValue(s(R.string.ai_title_deep));
        aiStatus.setValue(s(R.string.status_deep_manifest));
        ScanResult existing = scan.getValue();
        List<ProbeResult> currentProbes = probes.getValue();
        List<Finding> currentLogin = loginFindings.getValue();
        io.execute(() -> {
            try {
                String key = resolveKey(typedKey);
                if (key == null) {
                    return;
                }
                try {
                    AiClient.checkKey(key);
                } catch (AiClient.AiException ex) {
                    aiError.postValue(new Event<>(ex.getMessage()));
                    return;
                }
                ScanResult manifest = existing;
                String manifestNote = null;
                boolean sameApk = manifest != null && target.apkPath.equals(manifest.apkPath);
                if (!sameApk) {
                    try {
                        manifest = new ApkAnalyzer(getApplication()).analyze(target, message -> {
                            if (!Text.isBlank(message)) {
                                aiStatus.postValue(message);
                            }
                        });
                        scan.postValue(manifest);
                    } catch (AnalysisException ex) {
                        manifest = null;
                        manifestNote = ex.getMessage();
                    }
                }
                aiStatus.postValue(s(R.string.status_deep_extract));
                List<File> apks = apkFiles(target);
                if (apks.isEmpty()) {
                    aiError.postValue(new Event<>(s(R.string.err_apk_read)));
                    return;
                }
                ApkCodeContext context;
                try {
                    context = new ApkContextExtractor().extract(apks);
                } catch (java.util.zip.ZipException ex) {
                    aiError.postValue(new Event<>(s(R.string.err_apk_corrupt)));
                    return;
                } catch (java.io.IOException ex) {
                    aiError.postValue(new Event<>(s(R.string.err_apk_read)));
                    return;
                }
                String json = CodeContextSummarizer.summarize(
                        manifest,
                        currentProbes,
                        currentLogin,
                        context,
                        target.label,
                        target.packageName,
                        manifestNote);
                aiStatus.postValue(s(R.string.status_deep_ai));
                String answer = new AiClient().analyzeDeep(key, json);
                aiText.postValue(answer);
            } catch (AiClient.AiException ex) {
                aiError.postValue(new Event<>(ex.getMessage()));
            } catch (UnknownHostException ex) {
                aiError.postValue(new Event<>(s(R.string.err_no_network)));
            } catch (SocketTimeoutException ex) {
                aiError.postValue(new Event<>(s(R.string.err_timeout)));
            } catch (java.io.IOException ex) {
                aiError.postValue(new Event<>(s(R.string.err_network)));
            } catch (OutOfMemoryError ex) {
                aiError.postValue(new Event<>(s(R.string.err_oom)));
            } catch (Exception ex) {
                aiError.postValue(new Event<>(s(R.string.err_analysis)));
            } finally {
                aiRunning.postValue(false);
                aiStatus.postValue(null);
            }
        });
    }

    private String resolveKey(String typedKey) {
        try {
            String key = Text.trimToNull(typedKey);
            if (key == null) {
                key = prefs().getApiKey();
            }
            if (key == null) {
                aiError.postValue(new Event<>(s(R.string.key_missing)));
                return null;
            }
            return key;
        } catch (Exception ex) {
            aiError.postValue(new Event<>(s(R.string.key_unavailable)));
            return null;
        }
    }

    private List<File> apkFiles(SelectedTarget target) {
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        try {
            if (target.kind == SelectedTarget.Kind.INSTALLED && target.packageName != null) {
                android.content.pm.ApplicationInfo info = getApplication().getPackageManager()
                        .getApplicationInfo(target.packageName, 0);
                if (info.sourceDir != null) {
                    paths.add(info.sourceDir);
                }
                if (info.splitSourceDirs != null) {
                    Collections.addAll(paths, info.splitSourceDirs);
                }
            }
        } catch (Exception ignored) {
            paths.clear();
        }
        if (paths.isEmpty() && target.apkPath != null) {
            paths.add(target.apkPath);
        }
        List<File> files = new ArrayList<>();
        for (String path : paths) {
            File file = new File(path);
            if (file.isFile()) {
                files.add(file);
            }
        }
        return files;
    }

    private SecurePrefs prefs() throws Exception {
        if (securePrefs == null) {
            securePrefs = SecurePrefs.open(getApplication());
        }
        return securePrefs;
    }

    private String displayName(Uri uri) {
        try (Cursor cursor = getApplication().getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (index >= 0) {
                    return cursor.getString(index);
                }
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }

    private String s(int id) {
        return getApplication().getString(id);
    }

    private String s(int id, Object... args) {
        return getApplication().getString(id, args);
    }

    @Override
    protected void onCleared() {
        analysisToken.incrementAndGet();
        io.shutdownNow();
    }
}
