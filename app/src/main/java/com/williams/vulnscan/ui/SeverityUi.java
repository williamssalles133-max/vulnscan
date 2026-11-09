package com.williams.vulnscan.ui;

import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import com.williams.vulnscan.R;
import com.williams.vulnscan.model.Severity;

public final class SeverityUi {
    private SeverityUi() {
    }

    public static void styleChip(TextView view, Severity severity) {
        view.setTextColor(ContextCompat.getColor(view.getContext(), text(severity)));
        view.setBackground(chip(view.getContext(), bg(severity)));
    }

    public static int accent(Context context, Severity severity) {
        return ContextCompat.getColor(context, text(severity));
    }

    private static int text(Severity severity) {
        return switch (severity) {
            case ALTO -> R.color.severity_high;
            case MEDIO -> R.color.severity_medium;
            case BAIXO -> R.color.severity_low;
            case INFO -> R.color.severity_info;
        };
    }

    private static int bg(Severity severity) {
        return switch (severity) {
            case ALTO -> R.color.severity_high_bg;
            case MEDIO -> R.color.severity_medium_bg;
            case BAIXO -> R.color.severity_low_bg;
            case INFO -> R.color.severity_info_bg;
        };
    }

    static GradientDrawable chip(Context context, int colorRes) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setCornerRadius(99f * context.getResources().getDisplayMetrics().density);
        drawable.setColor(ContextCompat.getColor(context, colorRes));
        return drawable;
    }
}
