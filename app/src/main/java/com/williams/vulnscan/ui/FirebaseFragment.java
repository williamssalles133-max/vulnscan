package com.williams.vulnscan.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.snackbar.Snackbar;
import com.williams.vulnscan.R;
import com.williams.vulnscan.ScanViewModel;
import com.williams.vulnscan.Text;
import com.williams.vulnscan.databinding.FragmentFirebaseBinding;
import com.williams.vulnscan.databinding.ItemProbeBinding;
import com.williams.vulnscan.model.FirebaseHints;
import com.williams.vulnscan.model.ProbeResult;
import com.williams.vulnscan.model.ScanResult;

import java.util.List;

public class FirebaseFragment extends Fragment {
    private FragmentFirebaseBinding binding;
    private ScanViewModel viewModel;
    private long appliedScanAt = -1L;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        binding = FragmentFirebaseBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        viewModel = new ViewModelProvider(requireActivity()).get(ScanViewModel.class);
        binding.fillFromScan.setOnClickListener(v -> applyHints(true));
        binding.runProbes.setOnClickListener(v -> confirmProbe());
        viewModel.scan().observe(getViewLifecycleOwner(), this::onScan);
        viewModel.probes().observe(getViewLifecycleOwner(), this::showProbes);
        viewModel.probeRunning().observe(getViewLifecycleOwner(), running -> {
            boolean busy = Boolean.TRUE.equals(running);
            binding.progress.setVisibility(busy ? View.VISIBLE : View.GONE);
            binding.runProbes.setEnabled(!busy);
            binding.fillFromScan.setEnabled(!busy);
        });
        viewModel.firebaseError().observe(getViewLifecycleOwner(), event -> {
            if (event == null || !isAdded()) {
                return;
            }
            String message = event.getIfNotHandled();
            if (message != null) {
                Snackbar.make(requireActivity().findViewById(android.R.id.content), message, Snackbar.LENGTH_LONG).show();
            }
        });
    }

    private void onScan(ScanResult result) {
        if (binding == null) {
            return;
        }
        if (result == null || result.firebase == null || !result.firebase.hasAny()) {
            binding.detected.setText(R.string.firebase_not_detected);
            return;
        }
        binding.detected.setText(getString(R.string.firebase_detected, describe(result.firebase)));
        if (result.scannedAtMillis != appliedScanAt) {
            appliedScanAt = result.scannedAtMillis;
            fillEmpty(result.firebase);
        }
    }

    private void applyHints(boolean overwrite) {
        ScanResult result = viewModel.scan().getValue();
        if (result == null || result.firebase == null || !result.firebase.hasAny()) {
            Snackbar.make(requireActivity().findViewById(android.R.id.content), R.string.firebase_fill_empty, Snackbar.LENGTH_LONG).show();
            return;
        }
        if (overwrite) {
            setText(result.firebase.projectId, true, binding.projectId);
            setText(result.firebase.apiKey, true, binding.apiKey);
            setText(result.firebase.databaseUrl, true, binding.databaseUrl);
            setText(result.firebase.storageBucket, true, binding.bucket);
        } else {
            fillEmpty(result.firebase);
        }
    }

    private void fillEmpty(FirebaseHints hints) {
        setText(hints.projectId, false, binding.projectId);
        setText(hints.apiKey, false, binding.apiKey);
        setText(hints.databaseUrl, false, binding.databaseUrl);
        setText(hints.storageBucket, false, binding.bucket);
    }

    private static void setText(String value, boolean overwrite, com.google.android.material.textfield.TextInputEditText edit) {
        if (Text.isBlank(value) || edit == null) {
            return;
        }
        if (!overwrite && edit.getText() != null && edit.getText().length() > 0) {
            return;
        }
        edit.setText(value);
    }

    private void confirmProbe() {
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.probe_confirm_title)
                .setMessage(R.string.probe_confirm_message)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.probe_confirm_go, (dialog, which) -> viewModel.probe(readForm()))
                .show();
    }

    private FirebaseHints readForm() {
        return new FirebaseHints(text(binding.projectId), text(binding.apiKey), text(binding.databaseUrl), text(binding.bucket));
    }

    private static String text(com.google.android.material.textfield.TextInputEditText edit) {
        return edit.getText() == null ? "" : edit.getText().toString();
    }

    private void showProbes(List<ProbeResult> probes) {
        if (binding == null) {
            return;
        }
        binding.results.removeAllViews();
        if (probes == null || probes.isEmpty()) {
            binding.resultsTitle.setVisibility(View.GONE);
            return;
        }
        binding.resultsTitle.setVisibility(View.VISIBLE);
        LayoutInflater inflater = LayoutInflater.from(requireContext());
        for (ProbeResult probe : probes) {
            ItemProbeBinding card = ItemProbeBinding.inflate(inflater, binding.results, true);
            card.target.setText(probe.target);
            card.status.setText(probe.badge());
            card.explanation.setText(probe.explanation);
            ProbeUi.style(card.status, probe.status);
            card.accent.setBackgroundColor(ProbeUi.accent(requireContext(), probe.status));
        }
    }

    private static String describe(FirebaseHints hints) {
        StringBuilder builder = new StringBuilder();
        if (hints.projectId != null) {
            builder.append(hints.projectId);
        }
        if (hints.databaseUrl != null) {
            if (builder.length() > 0) {
                builder.append(" · ");
            }
            builder.append(hints.databaseUrl);
        }
        if (builder.length() == 0 && hints.apiKey != null) {
            builder.append("API key");
        }
        return builder.toString();
    }

    @Override
    public void onDestroyView() {
        binding = null;
        super.onDestroyView();
    }
}
