package com.williams.vulnscan.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.williams.vulnscan.R;
import com.williams.vulnscan.Text;
import com.williams.vulnscan.databinding.ItemFindingBinding;
import com.williams.vulnscan.databinding.ItemFindingHeaderBinding;
import com.williams.vulnscan.model.Finding;
import com.williams.vulnscan.model.Severity;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public final class FindingAdapter extends RecyclerView.Adapter<RecyclerView.ViewHolder> {
    private static final int TYPE_HEADER = 1;
    private static final int TYPE_ITEM = 2;

    private final List<Row> rows = new ArrayList<>();
    private final Map<Severity, Integer> positions = new EnumMap<>(Severity.class);

    public void submit(List<Finding> findings) {
        rows.clear();
        positions.clear();
        if (findings != null) {
            for (Severity severity : Severity.values()) {
                List<Finding> group = new ArrayList<>();
                for (Finding finding : findings) {
                    if (finding.severity == severity) {
                        group.add(finding);
                    }
                }
                if (group.isEmpty()) {
                    continue;
                }
                positions.put(severity, rows.size());
                rows.add(new Header(severity, group.size()));
                for (Finding finding : group) {
                    rows.add(new Item(finding));
                }
            }
        }
        notifyDataSetChanged();
    }

    public int positionOf(Severity severity) {
        Integer position = positions.get(severity);
        return position == null ? 0 : position;
    }

    @Override
    public int getItemViewType(int position) {
        return rows.get(position) instanceof Header ? TYPE_HEADER : TYPE_ITEM;
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        LayoutInflater inflater = LayoutInflater.from(parent.getContext());
        if (viewType == TYPE_HEADER) {
            return new HeaderHolder(ItemFindingHeaderBinding.inflate(inflater, parent, false));
        }
        return new ItemHolder(ItemFindingBinding.inflate(inflater, parent, false));
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        Row row = rows.get(position);
        if (holder instanceof HeaderHolder headerHolder && row instanceof Header header) {
            headerHolder.bind(header);
        } else if (holder instanceof ItemHolder itemHolder && row instanceof Item item) {
            itemHolder.bind(item.finding);
        }
    }

    @Override
    public int getItemCount() {
        return rows.size();
    }

    private interface Row {
    }

    private static final class Header implements Row {
        final Severity severity;
        final int count;

        Header(Severity severity, int count) {
            this.severity = severity;
            this.count = count;
        }
    }

    private static final class Item implements Row {
        final Finding finding;

        Item(Finding finding) {
            this.finding = finding;
        }
    }

    private static final class HeaderHolder extends RecyclerView.ViewHolder {
        private final ItemFindingHeaderBinding binding;

        HeaderHolder(ItemFindingHeaderBinding binding) {
            super(binding.getRoot());
            this.binding = binding;
        }

        void bind(Header header) {
            binding.headerTitle.setText(header.severity.label() + " · " + header.count);
            binding.headerTitle.setTextColor(SeverityUi.accent(binding.getRoot().getContext(), header.severity));
        }
    }

    private static final class ItemHolder extends RecyclerView.ViewHolder {
        private final ItemFindingBinding binding;

        ItemHolder(ItemFindingBinding binding) {
            super(binding.getRoot());
            this.binding = binding;
        }

        void bind(Finding finding) {
            Context context = binding.getRoot().getContext();
            binding.severity.setText(finding.severity.label());
            SeverityUi.styleChip(binding.severity, finding.severity);
            binding.accent.setBackgroundColor(SeverityUi.accent(context, finding.severity));
            binding.category.setText(finding.category);
            binding.title.setText(finding.title);
            binding.detail.setText(finding.detail);
            binding.location.setText(finding.location);
            if (Text.isBlank(finding.sensitiveValue)) {
                binding.value.setVisibility(View.GONE);
            } else {
                binding.value.setVisibility(View.VISIBLE);
                binding.value.setText(finding.sensitiveValue);
            }
            binding.getRoot().setOnLongClickListener(view -> {
                String text = finding.title + "\n" + finding.detail
                        + (Text.isBlank(finding.sensitiveValue) ? "" : "\n" + finding.sensitiveValue)
                        + "\n" + finding.location;
                ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
                if (clipboard != null) {
                    clipboard.setPrimaryClip(ClipData.newPlainText("achado", text));
                    Toast.makeText(context, R.string.copied, Toast.LENGTH_SHORT).show();
                }
                return true;
            });
        }
    }
}
