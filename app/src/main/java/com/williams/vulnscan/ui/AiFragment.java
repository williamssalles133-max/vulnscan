package com.williams.vulnscan.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.snackbar.Snackbar;
import com.williams.vulnscan.R;
import com.williams.vulnscan.ScanViewModel;
import com.williams.vulnscan.Text;
import com.williams.vulnscan.ai.MarkdownRenderer;
import com.williams.vulnscan.databinding.FragmentAiBinding;

public class AiFragment extends Fragment {
    private FragmentAiBinding binding;
    private ScanViewModel viewModel;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        binding = FragmentAiBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        viewModel = new ViewModelProvider(requireActivity()).get(ScanViewModel.class);
        binding.saveKey.setOnClickListener(v -> viewModel.saveKey(currentKey()));
        binding.removeKey.setOnClickListener(v -> {
            binding.apiKey.setText("");
            viewModel.clearKey();
        });
        binding.analyzeAi.setOnClickListener(v -> viewModel.analyzeWithAi(currentKey()));
        viewModel.keyMessage().observe(getViewLifecycleOwner(), message -> {
            if (binding != null && message != null) {
                binding.keyStatus.setText(message);
            }
        });
        viewModel.aiRunning().observe(getViewLifecycleOwner(), running -> {
            if (binding == null) {
                return;
            }
            boolean busy = Boolean.TRUE.equals(running);
            binding.progress.setVisibility(busy ? View.VISIBLE : View.GONE);
            binding.analyzeAi.setEnabled(!busy);
            binding.saveKey.setEnabled(!busy);
            binding.removeKey.setEnabled(!busy);
        });
        viewModel.aiText().observe(getViewLifecycleOwner(), text -> {
            if (binding == null || Text.isBlank(text)) {
                return;
            }
            binding.resultCard.setVisibility(View.VISIBLE);
            binding.resultText.setText(MarkdownRenderer.render(requireContext(), text));
        });
        viewModel.aiError().observe(getViewLifecycleOwner(), event -> {
            if (event == null || !isAdded()) {
                return;
            }
            String message = event.getIfNotHandled();
            if (message != null) {
                Snackbar.make(requireActivity().findViewById(android.R.id.content), message, Snackbar.LENGTH_LONG).show();
            }
        });
    }

    private String currentKey() {
        if (binding.apiKey.getText() == null) {
            return "";
        }
        return binding.apiKey.getText().toString();
    }

    @Override
    public void onDestroyView() {
        binding = null;
        super.onDestroyView();
    }
}
