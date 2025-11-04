package com.example.chitchatapp.repository;

import android.app.Application;
import android.util.Log;

import androidx.lifecycle.LiveData;

import com.example.chitchatapp.db.AppDatabase;
import com.example.chitchatapp.db.Message;
import com.example.chitchatapp.db.MessageDao;
import com.example.chitchatapp.network.NetworkManager;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;

// Manages data flow between UI (ViewModel), Database (Room), and Network (NetworkManager)
public class ChatRepository implements NetworkManager.MessageReceiver {

    private static final String TAG = "ChatRepository";

    private static volatile ChatRepository INSTANCE;

    private final MessageDao messageDao;
    private final NetworkManager networkManager;
    private final LiveData<List<Message>> allMessages;
    private final android.content.Context context;

    private final ExecutorService databaseExecutor;

    private static String currentUsername = "User";

    private ChatRepository(Application application) {
        this.context = application.getApplicationContext();
        AppDatabase db = AppDatabase.getInstance(application);
        messageDao = db.messageDao();
        allMessages = messageDao.getAllMessages();
        databaseExecutor = AppDatabase.databaseWriteExecutor;
        networkManager = new NetworkManager(application, this);
    }

    public static ChatRepository getInstance(Application application) {
        if (INSTANCE == null) {
            synchronized (ChatRepository.class) {
                if (INSTANCE == null) {
                    INSTANCE = new ChatRepository(application);
                }
            }
        }
        return INSTANCE;
    }

    public LiveData<List<Message>> getAllMessages() {
        return allMessages;
    }

    public LiveData<String> getHostIpAddress() {
        return networkManager.getHostIpAddress();
    }

    public LiveData<Boolean> getConnectionStatus() {
        return networkManager.getConnectionStatus();
    }

    // ---------------- USER SETUP ----------------

    public static void setUsername(String username) {
        if (username != null && !username.trim().isEmpty()) {
            currentUsername = username.trim();
        } else {
            currentUsername = "Anonymous";
        }
    }

    // ---------------- NETWORK COMMANDS ----------------

    public void hostChat() {
        networkManager.startHost(currentUsername);
    }

    public void joinChat(String hostIp) {
        networkManager.startClient(hostIp, currentUsername);
    }

    public void stopNetwork() {
        networkManager.stop();
    }

    // ---------------- SEND MESSAGES ----------------

    public void sendMessage(String text) {
        long timestamp = new Date().getTime();
        Message message = new Message(currentUsername, text, timestamp, true);
        insert(message);

        String uniqueId = message.getUniqueId();
        networkManager.sendMessage("MSG:" + uniqueId + ":" + text);
    }

    public void sendImageMessage(String filePath, String caption) {
        try {
            java.io.File imageFile = new java.io.File(filePath);
            long fileSize = imageFile.length();
            String fileName = imageFile.getName();
            long timestamp = new Date().getTime();

            Message message = new Message(currentUsername,
                    caption != null && !caption.isEmpty() ? caption : "📷 Image",
                    timestamp, true);
            message.setMessageType("image");
            message.setFilePath(filePath);
            message.setFileName(fileName);
            message.setFileSize(fileSize);
            insert(message);

            String uniqueId = message.getUniqueId();
            String base64Image = encodeFileToBase64(filePath);
            if (base64Image == null || base64Image.isEmpty()) {
                Log.e(TAG, "Failed to encode image, cannot send");
                return;
            }
            networkManager.sendMessage("IMG:" + uniqueId + ":" + (caption != null ? caption : "") + ":" + base64Image);
        } catch (Exception e) {
            Log.e(TAG, "Error sending image message", e);
        }
    }

    public void sendDocumentMessage(String filePath, String fileName, long fileSize) {
        try {
            long timestamp = new Date().getTime();

            Message message = new Message(currentUsername, "📎 " + fileName, timestamp, true);
            message.setMessageType("document");
            message.setFilePath(filePath);
            message.setFileName(fileName);
            message.setFileSize(fileSize);
            insert(message);

            String uniqueId = message.getUniqueId();
            String base64Doc = encodeFileToBase64(filePath);
            if (base64Doc == null || base64Doc.isEmpty()) {
                Log.e(TAG, "Failed to encode document, cannot send");
                return;
            }
            networkManager.sendMessage("DOC:" + uniqueId + ":" + fileName + ":" + fileSize + ":" + base64Doc);
        } catch (Exception e) {
            Log.e(TAG, "Error sending document message", e);
        }
    }

    private String encodeFileToBase64(String filePath) {
        try {
            java.io.File file = new java.io.File(filePath);
            java.io.FileInputStream fis = new java.io.FileInputStream(file);
            byte[] bytes = new byte[(int) file.length()];
            fis.read(bytes);
            fis.close();
            return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP);
        } catch (Exception e) {
            Log.e(TAG, "Error encoding file", e);
            return null;
        }
    }

    // ---------------- DATABASE ----------------

    private void insert(Message message) {
        databaseExecutor.execute(() -> {
            messageDao.insertMessage(message);
            Log.d(TAG, "Database insert successful: " + message.getSenderName() + ": " + message.getText());
        });
    }

    // ---------------- NETWORK CALLBACKS ----------------

    @Override
    public void onMessageReceived(String sender, String text) {
        if (sender != null && sender.equals(currentUsername)) {
            Log.d(TAG, "Ignoring echo of own message: " + text);
            return;
        }

        String uniqueId;
        String messageText = text;
        long timestamp = new Date().getTime();

        if (text.startsWith("MSG:")) {
            String[] parts = text.substring(4).split(":", 2);
            if (parts.length == 2) {
                uniqueId = parts[0];
                messageText = parts[1];
            } else {
                uniqueId = sender + "_" + timestamp;
            }
        } else {
            uniqueId = sender + "_" + timestamp;
        }

        Message message = new Message(sender, messageText, timestamp, false, uniqueId);
        message.setSentByUser(false); // ✅ safeguard
        insert(message);
        Log.d(TAG, "Received message saved: " + sender + ": " + messageText);
    }

    @Override
    public void onImageReceived(String uniqueId, String caption, String base64Data) {
        databaseExecutor.execute(() -> {
            try {
                String[] idParts = uniqueId.split("_");
                String sender = idParts.length > 0 ? idParts[0] : "Unknown";

                if (sender.equals(currentUsername)) return;

                byte[] imageBytes = android.util.Base64.decode(base64Data, android.util.Base64.NO_WRAP);
                java.io.File imagesDir = new java.io.File(context.getFilesDir(), "images");
                if (!imagesDir.exists()) imagesDir.mkdirs();

                java.io.File imageFile = new java.io.File(imagesDir, "img_" + System.currentTimeMillis() + ".jpg");
                java.io.FileOutputStream fos = new java.io.FileOutputStream(imageFile);
                fos.write(imageBytes);
                fos.close();

                long timestamp = System.currentTimeMillis();
                Message message = new Message(sender,
                        caption != null && !caption.isEmpty() ? caption : "📷 Image",
                        timestamp, false, uniqueId);
                message.setMessageType("image");
                message.setFilePath(imageFile.getAbsolutePath());
                message.setFileName(imageFile.getName());
                message.setFileSize(imageFile.length());
                message.setSentByUser(false); // ✅ fix
                insert(message);
                Log.d(TAG, "Received and saved image message: " + uniqueId);
            } catch (Exception e) {
                Log.e(TAG, "Error processing received image", e);
            }
        });
    }

    @Override
    public void onDocumentReceived(String uniqueId, String fileName, long fileSize, String base64Data) {
        databaseExecutor.execute(() -> {
            try {
                String[] idParts = uniqueId.split("_");
                String sender = idParts.length > 0 ? idParts[0] : "Unknown";

                if (sender.equals(currentUsername)) return;

                byte[] docBytes = android.util.Base64.decode(base64Data, android.util.Base64.NO_WRAP);
                java.io.File docsDir = new java.io.File(context.getFilesDir(), "documents");
                if (!docsDir.exists()) docsDir.mkdirs();

                // ✅ avoid overwriting same-named files
                java.io.File docFile = new java.io.File(docsDir, System.currentTimeMillis() + "_" + fileName);

                java.io.FileOutputStream fos = new java.io.FileOutputStream(docFile);
                fos.write(docBytes);
                fos.close();

                long timestamp = System.currentTimeMillis();
                Message message = new Message(sender, "📎 " + fileName, timestamp, false, uniqueId);
                message.setMessageType("document");
                message.setFilePath(docFile.getAbsolutePath());
                message.setFileName(fileName);
                message.setFileSize(fileSize);
                message.setSentByUser(false); // ✅ fix
                insert(message);
                Log.d(TAG, "Received and saved document message: " + uniqueId);
            } catch (Exception e) {
                Log.e(TAG, "Error processing received document", e);
            }
        });
    }

    @Override
    public void onMessageLiked(String uniqueId, boolean isLiked) {
        databaseExecutor.execute(() -> {
            Message message = messageDao.getMessageByUniqueId(uniqueId);
            if (message == null) return;

            String likedBy = message.getLikedBy();
            java.util.List<String> users = new java.util.ArrayList<>();
            if (likedBy != null && !likedBy.isEmpty()) {
                for (String u : likedBy.split(",")) {
                    if (!u.trim().isEmpty()) users.add(u.trim());
                }
            }

            if (isLiked) {
                if (!users.contains(currentUsername)) {
                    users.add(currentUsername);
                    messageDao.incrementLike(uniqueId);
                }
            } else {
                if (users.remove(currentUsername)) {
                    messageDao.decrementLike(uniqueId);
                }
            }

            String updated = users.isEmpty() ? null : String.join(",", users);
            messageDao.updateLikedBy(uniqueId, updated);
        });
    }

    @Override
    public void onMessageEdited(String uniqueId, String newText) {
        databaseExecutor.execute(() -> {
            messageDao.updateMessage(uniqueId, newText);
            Log.d(TAG, "Edited message updated locally: " + uniqueId);
        });
    }

    @Override
    public void onMessageDeleted(String uniqueId) {
        databaseExecutor.execute(() -> {
            messageDao.deleteMessage(uniqueId);
            Log.d(TAG, "Deleted message locally: " + uniqueId);
        });
    }

    // ---------------- PUBLIC ACTION METHODS ----------------

    public void likeMessage(int messageId, boolean dummy) { // dummy kept for compatibility
        databaseExecutor.execute(() -> {
            Message message = messageDao.getMessageById(messageId);
            if (message != null && message.getUniqueId() != null) {
                String uniqueId = message.getUniqueId();
                String likedBy = message.getLikedBy();
                List<String> likedByList = new ArrayList<>();

                if (likedBy != null && !likedBy.isEmpty()) {
                    String[] users = likedBy.split(",");
                    for (String user : users) {
                        if (user != null && !user.trim().isEmpty()) {
                            likedByList.add(user.trim());
                        }
                    }
                }

                boolean alreadyLiked = likedByList.contains(currentUsername);
                boolean willLike = !alreadyLiked; // toggle state

                if (willLike) {
                    likedByList.add(currentUsername);
                    messageDao.incrementLike(uniqueId);
                } else {
                    likedByList.remove(currentUsername);
                    messageDao.decrementLike(uniqueId);
                }

                String newLikedBy = likedByList.isEmpty() ? null : String.join(",", likedByList);
                messageDao.updateLikedBy(uniqueId, newLikedBy);

                // Send over network with correct intent
                networkManager.sendLike(uniqueId, willLike);
                Log.d(TAG, "Toggled like for " + uniqueId + " → " + (willLike ? "liked" : "unliked"));
            }
        });
    }



    public void editMessage(int messageId, String newText) {
        databaseExecutor.execute(() -> {
            Message message = messageDao.getMessageById(messageId);
            if (message != null && message.getUniqueId() != null) {
                String id = message.getUniqueId();
                onMessageEdited(id, newText);
                networkManager.sendEdit(id, newText);
            }
        });
    }

    public void deleteMessage(int messageId) {
        databaseExecutor.execute(() -> {
            Message message = messageDao.getMessageById(messageId);
            if (message != null && message.getUniqueId() != null) {
                String id = message.getUniqueId();
                onMessageDeleted(id);
                networkManager.sendDelete(id);
            }
        });
    }
}
