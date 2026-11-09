package com.williams.vulnscan.ui;

import android.content.Context;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import com.williams.vulnscan.R;
import com.williams.vulnscan.model.ProbeResult;

public final class ProbeUi {
    private ProbeUi() {
    }

    public static void style(TextView view, ProbeResult.Status status) {
        view.setTextColor(ContextCompat.getColor(view.getContext(), text(status)));
        view.setBackground(SeverityUi.chip(view.getContext(), bg(status)));
    }

    public static int accent(Context context, ProbeResult.Status status) {
        return ContextCompat.getColor(context, text(status));
    }

    private static int text(ProbeResult.Status status) {
        return switch (status) {
            case ABERTO -> R.color.severity_high;
            case PROTEGIDO -> R.color.severity_low;
            case INCONCLUSIVO -> R.color.severity_medium;
            case ERRO -> R.color.severity_info;
        };
    }

    private static int bg(ProbeResult.Status status) {
        return switch (status) {
            case ABERTO -> R.color.severity_high_bg;
            case PROTEGIDO -> R.color.severity_low_bg;
            case INCONCLUSIVO -> R.color.severity_medium_bg;
            case ERRO -> R.color.severity_info_bg;
        };
    }
}
