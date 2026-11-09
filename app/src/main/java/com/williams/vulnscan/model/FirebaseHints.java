package com.williams.vulnscan.model;

import com.williams.vulnscan.Text;

public final class FirebaseHints {
    public final String projectId;
    public final String apiKey;
    public final String databaseUrl;
    public final String storageBucket;

    public FirebaseHints(String projectId, String apiKey, String databaseUrl, String storageBucket) {
        this.projectId = Text.trimToNull(projectId);
        this.apiKey = Text.trimToNull(apiKey);
        this.databaseUrl = Text.trimToNull(databaseUrl);
        this.storageBucket = Text.trimToNull(storageBucket);
    }

    public boolean hasAny() {
        return projectId != null || apiKey != null || databaseUrl != null || storageBucket != null;
    }
}
