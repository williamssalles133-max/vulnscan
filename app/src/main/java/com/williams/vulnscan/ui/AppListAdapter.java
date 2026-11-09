package com.williams.vulnscan.ui;

import android.content.pm.PackageManager;
import android.view.LayoutInflater;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.williams.vulnscan.databinding.ItemAppBinding;
import com.williams.vulnscan.model.AppEntry;

import java.util.ArrayList;
import java.util.List;

public final class AppListAdapter extends RecyclerView.Adapter<AppListAdapter.Holder> {
    public interface Listener {
        void onApp(AppEntry app);
    }

    private final Listener listener;
    private final List<AppEntry> apps = new ArrayList<>();

    public AppListAdapter(Listener listener) {
        this.listener = listener;
    }

    public void submit(List<AppEntry> next) {
        apps.clear();
        if (next != null) {
            apps.addAll(next);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        return new Holder(ItemAppBinding.inflate(LayoutInflater.from(parent.getContext()), parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull Holder holder, int position) {
        holder.bind(apps.get(position), listener);
    }

    @Override
    public int getItemCount() {
        return apps.size();
    }

    static final class Holder extends RecyclerView.ViewHolder {
        private final ItemAppBinding binding;

        Holder(ItemAppBinding binding) {
            super(binding.getRoot());
            this.binding = binding;
        }

        void bind(AppEntry app, Listener listener) {
            binding.label.setText(app.label);
            binding.packageName.setText(app.packageName);
            try {
                PackageManager pm = binding.getRoot().getContext().getPackageManager();
                binding.icon.setImageDrawable(pm.getApplicationIcon(app.packageName));
            } catch (Exception ex) {
                binding.icon.setImageDrawable(null);
            }
            binding.getRoot().setOnClickListener(view -> listener.onApp(app));
        }
    }
}
