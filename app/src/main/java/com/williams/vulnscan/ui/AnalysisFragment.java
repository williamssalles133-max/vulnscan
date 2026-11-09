package com.williams.vulnscan.ui;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.snackbar.Snackbar;
import com.williams.vulnscan.R;
import com.williams.vulnscan.ScanViewModel;
import com.williams.vulnscan.Text;
import com.williams.vulnscan.databinding.FragmentAnalysisBinding;
import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.ScanResult;
import com.williams.vulnscan.model.SelectedTarget;
import com.williams.vulnscan.model.Severity;

import java.util.Collections;
import java.util.List;

public class AnalysisFragment extends Fragment {
    private FragmentAnalysisBinding binding;
    private ScanViewModel viewModel;
    private FindingAdapter adapter;
    private int iconToken;

    private final ActivityResultLauncher<String[]> openDocument = registerForActivityResult(
            new ActivityResultContracts.OpenDocument(),
            uri -> {
                if (uri != null && viewModel != null) {
                    viewModel.importApk(uri);
                }
            });

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        binding = FragmentAnalysisBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        viewModel = new ViewModelProvider(requireActivity()).get(ScanViewModel.class);
        adapter = new FindingAdapter();
        binding.findings.setAdapter(adapter);
        binding.findings.setItemAnimator(null);
        binding.pickInstalled.setOnClickListener(v ->
                new AppPickerSheet().show(getChildFragmentManager(), "apps"));
        binding.pickApk.setOnClickListener(v -> openDocument.launch(new String[]{
                "application/vnd.android.package-archive",
                "application/octet-stream",
                "*/*"
        }));
        binding.analyze.setOnClickListener(v -> viewModel.analyze());

        viewModel.selected().observe(getViewLifecycleOwner(), this::bindTarget);
        viewModel.scan().observe(getViewLifecycleOwner(), this::bindScan);
        viewModel.analysisRunning().observe(getViewLifecycleOwner(), running -> {
            boolean busy = Boolean.TRUE.equals(running);
            binding.progress.setVisibility(busy ? View.VISIBLE : View.GONE);
            binding.analyze.setEnabled(!busy && viewModel.selected().getValue() != null);
            binding.pickInstalled.setEnabled(!busy);
            binding.pickApk.setEnabled(!busy);
        });
        viewModel.analysisStatus().observe(getViewLifecycleOwner(), status -> {
            if (Text.isBlank(status)) {
                binding.status.setVisibility(View.GONE);
            } else {
                binding.status.setVisibility(View.VISIBLE);
                binding.status.setText(status);
            }
        });
        viewModel.analysisError().observe(getViewLifecycleOwner(), this::showError);
    }

    private void bindTarget(SelectedTarget target) {
        if (binding == null) {
            return;
        }
        boolean busy = Boolean.TRUE.equals(viewModel.analysisRunning().getValue());
        binding.analyze.setEnabled(target != null && !busy);
        if (target == null) {
            binding.targetLabel.setText(R.string.no_target);
            binding.targetPackage.setText(R.string.no_target_hint);
            binding.targetIcon.setVisibility(View.GONE);
            return;
        }
        binding.targetLabel.setText(target.label);
        binding.targetPackage.setText(target.packageName == null ? target.apkPath : target.packageName);
        int token = ++iconToken;
        binding.targetIcon.setVisibility(View.VISIBLE);
        binding.targetIcon.setImageDrawable(null);
        android.content.Context appContext = requireContext().getApplicationContext();
        String packageName = target.packageName;
        String apkPath = target.apkPath;
        SelectedTarget.Kind kind = target.kind;
        new Thread(() -> {
            Drawable icon = loadIcon(appContext, kind, packageName, apkPath);
            if (binding == null) {
                return;
            }
            binding.targetIcon.post(() -> {
                if (binding != null && token == iconToken && icon != null) {
                    binding.targetIcon.setImageDrawable(icon);
                }
            });
        }, "vulnscan-icon").start();
    }

    private void bindScan(ScanResult result) {
        if (binding == null) {
            return;
        }
        List<Finding> findings = result == null ? Collections.emptyList() : result.findings;
        adapter.submit(findings);
        binding.emptyState.setVisibility(findings.isEmpty() ? View.VISIBLE : View.GONE);
        binding.analyze.setText(result == null ? R.string.analyze : R.string.analyze_again);
        if (result != null) {
            binding.targetLabel.setText(result.label);
            binding.targetPackage.setText(result.packageName + " · " + result.versionName);
        }
        renderSummary(findings);
    }

    private void renderSummary(List<Finding> findings) {
        binding.summaryRow.removeAllViews();
        if (findings.isEmpty()) {
            binding.summaryScroll.setVisibility(View.GONE);
            return;
        }
        LayoutInflater inflater = LayoutInflater.from(requireContext());
        boolean any = false;
        for (Severity severity : Severity.values()) {
            int count = 0;
            for (Finding finding : findings) {
                if (finding.severity == severity) {
                    count++;
                }
            }
            if (count == 0) {
                continue;
            }
            any = true;
            TextView pill = (TextView) inflater.inflate(R.layout.item_summary_pill, binding.summaryRow, false);
            pill.setText(severity.label() + " " + count);
            SeverityUi.styleChip(pill, severity);
            pill.setOnClickListener(v -> binding.findings.smoothScrollToPosition(adapter.positionOf(severity)));
            binding.summaryRow.addView(pill);
        }
        binding.summaryScroll.setVisibility(any ? View.VISIBLE : View.GONE);
    }

    private static Drawable loadIcon(
            android.content.Context context,
            SelectedTarget.Kind kind,
            String packageName,
            String apkPath) {
        try {
            PackageManager pm = context.getPackageManager();
            if (kind == SelectedTarget.Kind.INSTALLED) {
                return pm.getApplicationIcon(packageName);
            }
            android.content.pm.PackageInfo info = pm.getPackageArchiveInfo(apkPath, 0);
            if (info != null && info.applicationInfo != null) {
                ApplicationInfo app = info.applicationInfo;
                app.sourceDir = apkPath;
                app.publicSourceDir = apkPath;
                return app.loadIcon(pm);
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }

    private void showError(com.williams.vulnscan.data.Event<String> event) {
        if (event == null || !isAdded()) {
            return;
        }
        String message = event.getIfNotHandled();
        if (message != null) {
            Snackbar.make(requireActivity().findViewById(android.R.id.content), message, Snackbar.LENGTH_LONG).show();
        }
    }

    @Override
    public void onDestroyView() {
        binding = null;
        super.onDestroyView();
    }
}
