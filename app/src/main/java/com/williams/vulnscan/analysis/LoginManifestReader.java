package com.williams.vulnscan.analysis;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import com.williams.vulnscan.model.SelectedTarget;

/**
 * Lê só a flag de texto puro do manifesto. Não altera o pacote analisado.
 */
public final class LoginManifestReader {
    /** {@code ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC} (@hide). */
    static final int FLAG_USES_CLEARTEXT_TRAFFIC = 1 << 27;

    public static final class Flags {
        public final boolean read;
        public final boolean cleartext;

        Flags(boolean read, boolean cleartext) {
            this.read = read;
            this.cleartext = cleartext;
        }
    }

    private LoginManifestReader() {
    }

    public static Flags read(Context context, SelectedTarget target) {
        if (target == null) {
            return new Flags(false, false);
        }
        try {
            PackageManager pm = context.getApplicationContext().getPackageManager();
            PackageInfo info = target.kind == SelectedTarget.Kind.INSTALLED
                    ? loadInstalled(pm, target.packageName)
                    : loadArchive(pm, target.apkPath);
            if (info == null || info.applicationInfo == null) {
                return new Flags(false, false);
            }
            boolean cleartext = (info.applicationInfo.flags & FLAG_USES_CLEARTEXT_TRAFFIC) != 0;
            return new Flags(true, cleartext);
        } catch (Exception ex) {
            return new Flags(false, false);
        }
    }

    private static PackageInfo loadInstalled(PackageManager pm, String packageName) throws PackageManager.NameNotFoundException {
        if (Build.VERSION.SDK_INT >= 33) {
            return pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0));
        }
        return loadInstalledLegacy(pm, packageName);
    }

    @SuppressWarnings("deprecation")
    private static PackageInfo loadInstalledLegacy(PackageManager pm, String packageName) throws PackageManager.NameNotFoundException {
        return pm.getPackageInfo(packageName, 0);
    }

    private static PackageInfo loadArchive(PackageManager pm, String path) {
        if (path == null) {
            return null;
        }
        if (Build.VERSION.SDK_INT >= 33) {
            return pm.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(0));
        }
        return loadArchiveLegacy(pm, path);
    }

    @SuppressWarnings("deprecation")
    private static PackageInfo loadArchiveLegacy(PackageManager pm, String path) {
        return pm.getPackageArchiveInfo(path, 0);
    }
}
