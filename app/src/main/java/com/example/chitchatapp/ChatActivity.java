package com.example.chitchatapp;

import android.app.AlertDialog;
import android.content.Context; // ADDED: Required for getSystemService and hideKeyboard
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Bundle;
import android.provider.MediaStore;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.chitchatapp.adapter.ChatAdapter;
import com.example.chitchatapp.viewmodel.ChatViewModel;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

public class ChatActivity extends AppCompatActivity {

    private static final String TAG = "ChatActivity";

    private ChatViewModel chatViewModel;
    private RecyclerView recyclerView;
    private ChatAdapter adapter;
    private EditText messageInput;
    private ImageButton sendButton, attachButton;
    private TextView statusText;

    private static final int REQUEST_IMAGE_PICK = 1001;
    private static final int REQUEST_DOCUMENT_PICK = 1002;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat);

        // --- View Initialization ---
        recyclerView = findViewById(R.id.recycler_view_messages);
        messageInput = findViewById(R.id.edit_text_message);
        sendButton = findViewById(R.id.button_send);
        attachButton = findViewById(R.id.button_attach);
        statusText = findViewById(R.id.text_status);

        // --- Setup ViewModel ---
        chatViewModel = new ViewModelProvider(this).get(ChatViewModel.class);

        // --- Setup RecyclerView and Adapter ---
        adapter = new ChatAdapter();
        adapter.setActionListener(new ChatAdapter.MessageActionListener() {
            @Override
            public void onLikeClicked(int messageId, boolean shouldLike) {
                // Fixed: Directly call likeMessage()
                chatViewModel.likeMessage(messageId, true);
            }

            @Override
            public void onEditClicked(int messageId, String currentText) {
                showEditDialog(messageId, currentText);
            }

            @Override
            public void onDeleteClicked(int messageId) {
                showDeleteConfirmation(messageId);
            }

            @Override
            public void onImageClicked(String filePath) {
                showImageFullScreen(filePath);
            }

            @Override
            public void onDocumentClicked(String filePath, String fileName) {
                openDocument(filePath, fileName);
            }

            @Override
            public void onLikesViewClicked(int messageId, java.util.List<String> likedByList) {
                showLikesDialog(likedByList);
            }
        });

        LinearLayoutManager layoutManager = new LinearLayoutManager(this);
        layoutManager.setStackFromEnd(true); // Messages stack from bottom
        recyclerView.setLayoutManager(layoutManager);
        recyclerView.setAdapter(adapter);

        // --- Initial Connection Status ---
        Intent intent = getIntent();
        if (Objects.equals(intent.getStringExtra("MODE"), "HOST")) {
            statusText.setText("Status: Starting Host...");
        } else {
            statusText.setText("Status: Connecting...");
        }

        // --- Observe Messages ---
        chatViewModel.getAllMessages().observe(this, messages -> {
            if (messages != null) {
                Log.d(TAG, "Message list updated. Size: " + messages.size());
                adapter.submitList(messages, () -> {
                    if (messages.size() > 0) {
                        recyclerView.smoothScrollToPosition(messages.size() - 1);
                    }
                });
            }
        });

        // --- Observe Host IP ---
        chatViewModel.getHostIpAddress().observe(this, ipAddress -> {
            if (ipAddress != null && !ipAddress.isEmpty()) {
                statusText.setText(ipAddress);
            }
        });

        // --- Observe Connection Status ---
        chatViewModel.getConnectionStatus().observe(this, isConnected -> {
            if (isConnected != null && !isConnected) {
                Toast.makeText(this, "Connection Lost or Failed.", Toast.LENGTH_LONG).show();
                statusText.setText("Status: Disconnected/Failed");
            } else if (isConnected != null && isConnected) {
                Intent i = getIntent();
                if (Objects.equals(i.getStringExtra("MODE"), "JOIN")) {
                    statusText.setText("Connected to: " + i.getStringExtra("HOST_IP"));
                }
            }
        });

        // --- Send Button ---
        sendButton.setOnClickListener(v -> {
            String text = messageInput.getText().toString().trim();
            if (!text.isEmpty()) {
                chatViewModel.sendMessage(text);
                messageInput.setText("");
                // ADDED: Hide keyboard after sending message
                hideKeyboard();
            }
        });

        // --- Attach Button ---
        attachButton.setOnClickListener(v -> showAttachmentOptions());
    }

    // ADDED: Helper method to dismiss the software keyboard
    private void hideKeyboard() {
        View view = this.getCurrentFocus();
        if (view != null) {
            android.view.inputmethod.InputMethodManager imm =
                    (android.view.inputmethod.InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
            if (imm != null) { // Null check for safety
                imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
            }
        }
    }

    private void showAttachmentOptions() {
        String[] options = {"Send Image", "Send Document"};
        new AlertDialog.Builder(this)
                .setTitle("Attach File")
                .setItems(options, (dialog, which) -> {
                    if (which == 0) {
                        pickImage();
                    } else {
                        pickDocument();
                    }
                })
                .show();
    }

    private void pickImage() {
        Intent intent = new Intent(Intent.ACTION_PICK, MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
        startActivityForResult(intent, REQUEST_IMAGE_PICK);
    }

    private void pickDocument() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        String[] mimeTypes = {"application/pdf", "text/plain", "application/msword",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"};
        intent.putExtra(Intent.EXTRA_MIME_TYPES, mimeTypes);
        startActivityForResult(Intent.createChooser(intent, "Select Document"), REQUEST_DOCUMENT_PICK);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            if (uri != null) {
                if (requestCode == REQUEST_IMAGE_PICK) {
                    handleImageSelection(uri);
                } else if (requestCode == REQUEST_DOCUMENT_PICK) {
                    handleDocumentSelection(uri);
                }
            }
        }
    }

    private void handleImageSelection(Uri imageUri) {
        try {
            // NEW: Use try-with-resources to ensure inputStream is automatically closed
            try (InputStream inputStream = getContentResolver().openInputStream(imageUri)) {
                if (inputStream == null) {
                    Toast.makeText(this, "Failed to open image stream", Toast.LENGTH_SHORT).show();
                    return;
                }
                Bitmap bitmap = BitmapFactory.decodeStream(inputStream);

                File imageFile = saveImageToStorage(bitmap);
                if (imageFile != null) {
                    String caption = messageInput.getText().toString().trim();
                    chatViewModel.sendImageMessage(imageFile.getAbsolutePath(), caption);
                    messageInput.setText("");
                } else {
                    Toast.makeText(this, "Failed to process image", Toast.LENGTH_SHORT).show();
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error handling image selection", e);
        }
    }

    private void handleDocumentSelection(Uri documentUri) {
        try {
            String fileName = getFileName(documentUri);
            File documentFile = saveDocumentToStorage(documentUri, fileName);
            if (documentFile != null) {
                chatViewModel.sendDocumentMessage(documentFile.getAbsolutePath(), fileName, documentFile.length());
                messageInput.setText("");
            } else {
                Toast.makeText(this, "Failed to process document", Toast.LENGTH_SHORT).show();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error handling document selection", e);
        }
    }

    private File saveImageToStorage(Bitmap bitmap) {
        try {
            File imagesDir = new File(getFilesDir(), "images");
            if (!imagesDir.exists()) imagesDir.mkdirs();
            File imageFile = new File(imagesDir, "img_" + System.currentTimeMillis() + ".jpg");
            FileOutputStream fos = new FileOutputStream(imageFile);
            bitmap.compress(Bitmap.CompressFormat.JPEG, 85, fos);
            fos.close();
            return imageFile;
        } catch (Exception e) {
            Log.e(TAG, "Error saving image", e);
            return null;
        }
    }

    private File saveDocumentToStorage(Uri documentUri, String fileName) {
        try {
            File docsDir = new File(getFilesDir(), "documents");
            if (!docsDir.exists()) docsDir.mkdirs();
            File docFile = new File(docsDir, fileName);
            InputStream inputStream = getContentResolver().openInputStream(documentUri);
            OutputStream outputStream = new FileOutputStream(docFile);
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            inputStream.close();
            outputStream.close();
            return docFile;
        } catch (Exception e) {
            Log.e(TAG, "Error saving document", e);
            return null;
        }
    }

    private String getFileName(Uri uri) {
        String result = null;
        if ("content".equals(uri.getScheme())) {
            try (android.database.Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME);
                    if (nameIndex != -1) {
                        result = cursor.getString(nameIndex);
                    }
                }
            }
        }
        if (result == null) {
            result = uri.getPath();
            int cut = result.lastIndexOf('/');
            if (cut != -1) {
                result = result.substring(cut + 1);
            }
        }
        return result != null ? result : "document_" + System.currentTimeMillis();
    }

    private void showImageFullScreen(String filePath) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        ImageView imageView = new ImageView(this);
        Bitmap bitmap = BitmapFactory.decodeFile(filePath);
        if (bitmap != null) {
            imageView.setImageBitmap(bitmap);
            imageView.setAdjustViewBounds(true);
            imageView.setScaleType(ImageView.ScaleType.FIT_CENTER);
            builder.setView(imageView);
            builder.setPositiveButton("Close", null);
            builder.show();
        }
    }

    private void openDocument(String filePath, String fileName) {
        File file = new File(filePath);
        if (file.exists()) {
            Intent intent = new Intent(Intent.ACTION_VIEW);
            String mimeType = getMimeType(fileName);
            try {
                Uri uri = androidx.core.content.FileProvider.getUriForFile(this,
                        getPackageName() + ".fileprovider", file);
                intent.setDataAndType(uri, mimeType);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
                startActivity(intent);
            } catch (Exception e) {
                try {
                    Uri uri = Uri.fromFile(file);
                    intent.setDataAndType(uri, mimeType);
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivity(intent);
                } catch (Exception e2) {
                    Log.e(TAG, "Error opening document", e2);
                    Toast.makeText(this, "No app available to open this file", Toast.LENGTH_SHORT).show();
                }
            }
        } else {
            Toast.makeText(this, "File not found", Toast.LENGTH_SHORT).show();
        }
    }

    private String getMimeType(String fileName) {
        String extension = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        switch (extension) {
            case "pdf": return "application/pdf";
            case "txt": return "text/plain";
            case "doc": return "application/msword";
            case "docx": return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
            default: return "*/*";
        }
    }

    private void showLikesDialog(java.util.List<String> likedByList) {
        if (likedByList == null || likedByList.isEmpty()) {
            Toast.makeText(this, "No one has liked this message yet", Toast.LENGTH_SHORT).show();
            return;
        }
        StringBuilder message = new StringBuilder("Liked by:\n");
        for (int i = 0; i < likedByList.size(); i++) {
            message.append("• ").append(likedByList.get(i));
            if (i < likedByList.size() - 1) message.append("\n");
        }
        new AlertDialog.Builder(this)
                .setTitle("Who Liked This Message")
                .setMessage(message.toString())
                .setPositiveButton("OK", null)
                .show();
    }

    private void showEditDialog(int messageId, String currentText) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Edit Message");
        final EditText input = new EditText(this);
        input.setText(currentText);
        input.setSelection(currentText.length());
        builder.setView(input);
        builder.setPositiveButton("Save", (dialog, which) -> {
            String newText = input.getText().toString().trim();
            if (!newText.isEmpty()) {
                chatViewModel.editMessage(messageId, newText);
            }
        });
        builder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());
        builder.show();
    }

    private void showDeleteConfirmation(int messageId) {
        new AlertDialog.Builder(this)
                .setTitle("Delete Message")
                .setMessage("Are you sure you want to delete this message?")
                .setPositiveButton("Delete", (dialog, which) -> chatViewModel.deleteMessage(messageId))
                .setNegativeButton("Cancel", null)
                .show();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        chatViewModel.stopNetwork();
    }
}