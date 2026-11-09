package com.williams.vulnscan.ai;

import android.content.Context;
import android.graphics.Typeface;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.LeadingMarginSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;

import androidx.core.content.ContextCompat;

import com.williams.vulnscan.R;

public final class MarkdownRenderer {
    private MarkdownRenderer() {
    }

    public static CharSequence render(Context context, String markdown) {
        if (markdown == null || markdown.isEmpty()) {
            return "";
        }
        int accent = ContextCompat.getColor(context, R.color.primary);
        SpannableStringBuilder out = new SpannableStringBuilder();
        String[] lines = markdown.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        boolean code = false;
        for (String line : lines) {
            if (line.trim().startsWith("```")) {
                code = !code;
                continue;
            }
            if (out.length() > 0) {
                out.append('\n');
            }
            if (code) {
                int start = out.length();
                out.append(line);
                out.setSpan(new TypefaceSpan("monospace"), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                out.setSpan(new ForegroundColorSpan(accent), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                continue;
            }
            String trimmed = line.trim();
            int heading = 0;
            while (heading < trimmed.length() && trimmed.charAt(heading) == '#') {
                heading++;
            }
            if (heading > 0 && heading <= 3 && trimmed.length() > heading && trimmed.charAt(heading) == ' ') {
                int start = out.length();
                appendInline(out, trimmed.substring(heading + 1).trim(), accent);
                out.setSpan(new StyleSpan(Typeface.BOLD), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                float size = heading == 1 ? 1.3f : heading == 2 ? 1.16f : 1.05f;
                out.setSpan(new RelativeSizeSpan(size), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                continue;
            }
            if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
                int start = out.length();
                out.append("• ");
                appendInline(out, trimmed.substring(2), accent);
                int margin = dp(context, 12);
                out.setSpan(new LeadingMarginSpan.Standard(margin, margin), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                continue;
            }
            appendInline(out, line, accent);
        }
        return out;
    }

    private static void appendInline(SpannableStringBuilder out, String text, int accent) {
        int index = 0;
        while (index < text.length()) {
            if (text.startsWith("**", index)) {
                int end = text.indexOf("**", index + 2);
                if (end > index) {
                    int start = out.length();
                    appendCode(out, text.substring(index + 2, end), accent);
                    out.setSpan(new StyleSpan(Typeface.BOLD), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    index = end + 2;
                    continue;
                }
            }
            if (text.charAt(index) == '`') {
                int end = text.indexOf('`', index + 1);
                if (end > index) {
                    int start = out.length();
                    out.append(text, index + 1, end);
                    out.setSpan(new TypefaceSpan("monospace"), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    out.setSpan(new ForegroundColorSpan(accent), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    index = end + 1;
                    continue;
                }
            }
            out.append(text.charAt(index));
            index++;
        }
    }

    private static void appendCode(SpannableStringBuilder out, String text, int accent) {
        int index = 0;
        while (index < text.length()) {
            if (text.charAt(index) == '`') {
                int end = text.indexOf('`', index + 1);
                if (end > index) {
                    int start = out.length();
                    out.append(text, index + 1, end);
                    out.setSpan(new TypefaceSpan("monospace"), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    out.setSpan(new ForegroundColorSpan(accent), start, out.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    index = end + 1;
                    continue;
                }
            }
            out.append(text.charAt(index));
            index++;
        }
    }

    private static int dp(Context context, int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }
}
