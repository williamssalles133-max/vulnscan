package com.williams.vulnscan.analysis;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Build;

import com.williams.vulnscan.model.AppEntry;

import java.text.Collator;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class InstalledAppLister {
    public static final class Result {
        public final List<AppEntry> apps;
        public final boolean launcherOnly;

        Result(List<AppEntry> apps, boolean launcherOnly) {
            this.apps = apps;
            this.launcherOnly = launcherOnly;
        }
    }

    private final Context context;

    public InstalledAppLister(Context context) {
        this.context = context.getApplicationContext();
    }

    public Result list(boolean includeSystem) {
        PackageManager pm = context.getPackageManager();
        boolean canQueryAll = Build.VERSION.SDK_INT < 30
                || context.checkSelfPermission(Manifest.permission.QUERY_ALL_PACKAGES) == PackageManager.PERMISSION_GRANTED;
        Map<String, ApplicationInfo> byPackage = new LinkedHashMap<>();
        boolean launcherOnly = false;
        try {
            if (canQueryAll) {
                for (ApplicationInfo info : pm.getInstalledApplications(0)) {
                    byPackage.put(info.packageName, info);
                }
            } else {
                launcherOnly = true;
                collectLaunchable(pm, byPackage);
            }
        } catch (RuntimeException ex) {
            byPackage.clear();
            launcherOnly = true;
            try {
                collectLaunchable(pm, byPackage);
            } catch (RuntimeException ignored) {
                return new Result(new ArrayList<>(), true);
            }
        }
        List<AppEntry> apps = new ArrayList<>();
        for (ApplicationInfo info : byPackage.values()) {
            boolean system = (info.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (system && !includeSystem) {
                continue;
            }
            String label;
            try {
                CharSequence loaded = pm.getApplicationLabel(info);
                label = loaded == null || loaded.length() == 0 ? info.packageName : loaded.toString();
            } catch (RuntimeException ex) {
                label = info.packageName;
            }
            apps.add(new AppEntry(label, info.packageName, system));
        }
        Collator collator = Collator.getInstance(new Locale("pt", "BR"));
        apps.sort((left, right) -> collator.compare(left.label, right.label));
        return new Result(apps, launcherOnly);
    }

    private static void collectLaunchable(PackageManager pm, Map<String, ApplicationInfo> byPackage) {
        Intent intent = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        List<ResolveInfo> resolved = pm.queryIntentActivities(intent, 0);
        for (ResolveInfo info : resolved) {
            if (info.activityInfo == null || info.activityInfo.applicationInfo == null) {
                continue;
            }
            ApplicationInfo app = info.activityInfo.applicationInfo;
            byPackage.put(app.packageName, app);
        }
    }
}
