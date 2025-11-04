package com.example.chitchatapp;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;

import com.example.chitchatapp.viewmodel.ChatViewModel;

public class MainActivity extends AppCompatActivity {

    private ChatViewModel chatViewModel;
    private EditText nameInput, ipInput;
    private Button hostButton, joinButton;
    private ProgressBar loadingIndicator;
    private TextView titleText;

    // Flag to prevent double navigation
    private boolean isNavigating = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        titleText = findViewById(R.id.text_app_title);
        nameInput = findViewById(R.id.edit_text_name);
        ipInput = findViewById(R.id.edit_text_ip);
        hostButton = findViewById(R.id.button_host);
        joinButton = findViewById(R.id.button_join);
        loadingIndicator = findViewById(R.id.loading_indicator);

        chatViewModel = new ViewModelProvider(this).get(ChatViewModel.class);

        hostButton.setOnClickListener(v -> {
            String name = nameInput.getText().toString().trim();
            if (validateName(name)) {
                showLoading("Hosting chat...");
                chatViewModel.setUsername(name);
                chatViewModel.hostChat();
            }
        });

        joinButton.setOnClickListener(v -> {
            String name = nameInput.getText().toString().trim();
            String hostIp = ipInput.getText().toString().trim();
            if (validateName(name) && validateIp(hostIp)) {
                showLoading("Joining chat...");
                chatViewModel.setUsername(name);
                chatViewModel.joinChat(hostIp);
            }
        });

        observeViewModel();
    }

    private void observeViewModel() {
        // Observer for HOST
        chatViewModel.getHostIpAddress().observe(this, hostIp -> {
            if (hostIp != null && !hostIp.isEmpty()) {
                // *** THIS IS THE NEW LOGIC ***
                if (hostIp.startsWith("Hosting on:")) {
                    // This is a SUCCESS
                    if (!isNavigating) {
                        isNavigating = true;
                        Intent intent = new Intent(MainActivity.this, ChatActivity.class);
                        intent.putExtra("MODE", "HOST");
                        startActivity(intent);
                        hideLoading(); // Hide on success
                    }
                } else if (hostIp.startsWith("Host failed:")) {
                    // This is a FAILURE
                    hideLoading(); // Hide on failure
                    Toast.makeText(this, hostIp, Toast.LENGTH_LONG).show();
                }
            }
        });

        // Observer for CLIENT
        chatViewModel.getConnectionStatus().observe(this, isConnected -> {
            if (isConnected) {
                if (!isNavigating) {
                    isNavigating = true;
                    Intent intent = new Intent(MainActivity.this, ChatActivity.class);
                    intent.putExtra("MODE", "JOIN");
                    intent.putExtra("HOST_IP", ipInput.getText().toString().trim());
                    startActivity(intent);
                    hideLoading();
                }
            } else {
                // Connection failed (or was false initially)
                hideLoading();
                // Only show "failed" if they were trying to connect
                if (loadingIndicator.getVisibility() == View.VISIBLE) {
                    Toast.makeText(this, "Failed to connect to host", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private boolean validateName(String name) {
        if (name.isEmpty()) {
            nameInput.setError("Please enter a name");
            return false;
        }
        return true;
    }

    private boolean validateIp(String ip) {
        if (ip.isEmpty()) {
            ipInput.setError("Please enter an IP address");
            return false;
        }
        return true;
    }

    private void showLoading(String message) {
        titleText.setText(message);
        loadingIndicator.setVisibility(View.VISIBLE);
        hostButton.setEnabled(false);
        joinButton.setEnabled(false);
        nameInput.setEnabled(false);
        ipInput.setEnabled(false);
    }

    private void hideLoading() {
        titleText.setText(R.string.app_name); // Reset title
        loadingIndicator.setVisibility(View.GONE);
        hostButton.setEnabled(true);
        joinButton.setEnabled(true);
        nameInput.setEnabled(true);
        ipInput.setEnabled(true);
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Reset state on return to this screen
        isNavigating = false;
        hideLoading();
    }
}

