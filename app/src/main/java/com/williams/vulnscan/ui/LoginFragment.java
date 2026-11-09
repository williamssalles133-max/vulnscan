package com.williams.vulnscan.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.snackbar.Snackbar;
import com.williams.vulnscan.R;
import com.williams.vulnscan.ScanViewModel;
import com.williams.vulnscan.Text;
import com.williams.vulnscan.databinding.FragmentLoginBinding;
import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.SelectedTarget;
import com.williams.vulnscan.model.Severity;

import java.util.Collections;
import java.util.List;

public class LoginFragment extends Fragment {
    private FragmentLoginBinding binding;
    private ScanViewModel viewModel;
    private FindingAdapter adapter;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        binding = FragmentLoginBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        viewModel = new ViewModelProvider(requireActivity()).get(ScanViewModel.class);
        adapter = new FindingAdapter();
        binding.findings.setAdapter(adapter);
        binding.findings.setItemAnimator(null);
        binding.checkLogin.setOnClickListener(v -> viewModel.analyzeLogin());
        viewModel.selected().observe(getViewLifecycleOwner(), this::bindTarget);
        viewModel.loginFindings().observe(getViewLifecycleOwner(), this::bindFindings);
        viewModel.loginRunning().observe(getViewLifecycleOwner(), running -> {
            if (binding == null) {
                return;
            }
            boolean busy = Boolean.TRUE.equals(running);
            binding.progress.setVisibility(busy ? View.VISIBLE : View.GONE);
            binding.checkLogin.setEnabled(!busy);
        });
        viewModel.loginStatus().observe(getViewLifecycleOwner(), status -> {
            if (binding == null) {
                return;
            }
            if (Text.isBlank(status)) {
                binding.status.setVisibility(View.GONE);
            } else {
                binding.status.setVisibility(View.VISIBLE);
                binding.status.setText(status);
            }
        });
        viewModel.loginError().observe(getViewLifecycleOwner(), event -> {
            if (event == null || !isAdded()) {
                return;
            }
            String message = event.getIfNotHandled();
            if (message != null) {
                Snackbar.make(requireActivity().findViewById(android.R.id.content), message, Snackbar.LENGTH_LONG).show();
            }
        });
    }

    private void bindTarget(SelectedTarget target) {
        if (binding == null) {
            return;
        }
        if (target == null) {
            binding.target.setText(R.string.login_no_target);
            return;
        }
        String packageName = target.packageName == null ? target.apkPath : target.packageName;
        binding.target.setText(target.label + "\n" + packageName);
    }

    private void bindFindings(List<Finding> findings) {
        if (binding == null) {
            return;
        }
        List<Finding> safe = findings == null ? Collections.emptyList() : findings;
        adapter.submit(safe);
        binding.emptyState.setVisibility(safe.isEmpty() ? View.VISIBLE : View.GONE);
        binding.checkLogin.setText(safe.isEmpty() ? R.string.login_check : R.string.login_check_again);
        binding.summaryRow.removeAllViews();
        if (safe.isEmpty()) {
            binding.summaryScroll.setVisibility(View.GONE);
            return;
        }
        LayoutInflater inflater = LayoutInflater.from(requireContext());
        for (Severity severity : Severity.values()) {
            int count = 0;
            for (Finding finding : safe) {
                if (finding.severity == severity) {
                    count++;
                }
            }
            if (count == 0) {
                continue;
            }
            TextView pill = (TextView) inflater.inflate(R.layout.item_summary_pill, binding.summaryRow, false);
            pill.setText(severity.label() + " " + count);
            SeverityUi.styleChip(pill, severity);
            pill.setOnClickListener(v -> binding.findings.smoothScrollToPosition(adapter.positionOf(severity)));
            binding.summaryRow.addView(pill);
        }
        binding.summaryScroll.setVisibility(View.VISIBLE);
    }

    @Override
    public void onDestroyView() {
        binding = null;
        super.onDestroyView();
    }
}
