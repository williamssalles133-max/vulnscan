package com.williams.vulnscan;

import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;

import com.google.android.material.tabs.TabLayoutMediator;
import com.williams.vulnscan.databinding.ActivityMainBinding;
import com.williams.vulnscan.ui.AiFragment;
import com.williams.vulnscan.ui.AnalysisFragment;
import com.williams.vulnscan.ui.FirebaseFragment;
import com.williams.vulnscan.ui.LoginFragment;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        binding.pager.setAdapter(new MainPagerAdapter(this));
        binding.pager.setOffscreenPageLimit(3);
        new TabLayoutMediator(binding.tabs, binding.pager, (tab, position) -> {
            int label = switch (position) {
                case 0 -> R.string.tab_analysis;
                case 1 -> R.string.tab_firebase;
                case 2 -> R.string.tab_login;
                default -> R.string.tab_ai;
            };
            tab.setText(label);
        }).attach();
    }

    private static final class MainPagerAdapter extends FragmentStateAdapter {
        MainPagerAdapter(@NonNull FragmentActivity activity) {
            super(activity);
        }

        @Override
        public int getItemCount() {
            return 4;
        }

        @NonNull
        @Override
        public Fragment createFragment(int position) {
            return switch (position) {
                case 0 -> new AnalysisFragment();
                case 1 -> new FirebaseFragment();
                case 2 -> new LoginFragment();
                default -> new AiFragment();
            };
        }
    }
}
