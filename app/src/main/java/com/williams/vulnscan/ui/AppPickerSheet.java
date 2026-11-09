package com.williams.vulnscan.ui;

import android.app.Dialog;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.snackbar.Snackbar;
import com.williams.vulnscan.R;
import com.williams.vulnscan.ScanViewModel;
import com.williams.vulnscan.analysis.InstalledAppLister;
import com.williams.vulnscan.databinding.SheetAppsBinding;
import com.williams.vulnscan.model.AppEntry;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AppPickerSheet extends BottomSheetDialogFragment {
    private SheetAppsBinding binding;
    private ScanViewModel viewModel;
    private AppListAdapter adapter;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private List<AppEntry> all = new ArrayList<>();

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        binding = SheetAppsBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        viewModel = new ViewModelProvider(requireActivity()).get(ScanViewModel.class);
        adapter = new AppListAdapter(app -> {
            viewModel.selectInstalled(app.packageName);
            dismiss();
        });
        binding.apps.setAdapter(adapter);
        binding.search.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                applyFilter();
            }
        });
        binding.systemSwitch.setOnCheckedChangeListener((button, checked) -> load(checked));
        load(false);
    }

    @Override
    public void onStart() {
        super.onStart();
        Dialog dialog = getDialog();
        if (!(dialog instanceof BottomSheetDialog sheetDialog)) {
            return;
        }
        FrameLayout sheet = sheetDialog.findViewById(com.google.android.material.R.id.design_bottom_sheet);
        if (sheet == null) {
            return;
        }
        ViewGroup.LayoutParams params = sheet.getLayoutParams();
        params.height = ViewGroup.LayoutParams.MATCH_PARENT;
        sheet.setLayoutParams(params);
        BottomSheetBehavior<FrameLayout> behavior = BottomSheetBehavior.from(sheet);
        behavior.setFitToContents(false);
        behavior.setSkipCollapsed(true);
        behavior.setState(BottomSheetBehavior.STATE_EXPANDED);
    }

    private void load(boolean includeSystem) {
        if (binding == null) {
            return;
        }
        binding.progress.setVisibility(View.VISIBLE);
        binding.empty.setVisibility(View.GONE);
        android.content.Context appContext = requireContext().getApplicationContext();
        executor.execute(() -> {
            InstalledAppLister.Result result;
            try {
                result = new InstalledAppLister(appContext).list(includeSystem);
            } catch (Exception ex) {
                if (isAdded()) {
                    requireActivity().runOnUiThread(() -> {
                        if (!isAdded()) {
                            return;
                        }
                        Snackbar.make(requireActivity().findViewById(android.R.id.content), R.string.apps_failed, Snackbar.LENGTH_LONG).show();
                        dismissAllowingStateLoss();
                    });
                }
                return;
            }
            if (!isAdded()) {
                return;
            }
            requireActivity().runOnUiThread(() -> {
                if (binding == null) {
                    return;
                }
                all = result.apps;
                binding.progress.setVisibility(View.GONE);
                binding.limited.setVisibility(result.launcherOnly ? View.VISIBLE : View.GONE);
                applyFilter();
            });
        });
    }

    private void applyFilter() {
        if (binding == null) {
            return;
        }
        String query = binding.search.getText() == null
                ? ""
                : binding.search.getText().toString().trim().toLowerCase(new Locale("pt", "BR"));
        List<AppEntry> shown = new ArrayList<>();
        for (AppEntry app : all) {
            String label = app.label.toLowerCase(new Locale("pt", "BR"));
            String pkg = app.packageName.toLowerCase(Locale.US);
            if (query.isEmpty() || label.contains(query) || pkg.contains(query)) {
                shown.add(app);
            }
        }
        adapter.submit(shown);
        binding.empty.setVisibility(shown.isEmpty() ? View.VISIBLE : View.GONE);
    }

    @Override
    public void onDestroyView() {
        binding = null;
        super.onDestroyView();
    }

    @Override
    public void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }
}
