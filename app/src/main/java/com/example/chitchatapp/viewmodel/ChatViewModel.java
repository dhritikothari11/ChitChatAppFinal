package com.example.chitchatapp.viewmodel;

import android.app.Application;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;

import com.example.chitchatapp.db.Message;
import com.example.chitchatapp.repository.ChatRepository;

import java.util.List;

public class ChatViewModel extends AndroidViewModel {

    private final ChatRepository repository;
    private final LiveData<List<Message>> allMessages;
    private final LiveData<String> hostIpAddress;
    private final LiveData<Boolean> connectionStatus;

    public ChatViewModel(@NonNull Application application) {
        super(application);
        repository = ChatRepository.getInstance(application);
        allMessages = repository.getAllMessages();
        hostIpAddress = repository.getHostIpAddress();
        connectionStatus = repository.getConnectionStatus();
    }

    // ------------------- LiveData Access -------------------

    public LiveData<List<Message>> getAllMessages() {
        return allMessages;
    }

    public LiveData<String> getHostIpAddress() {
        return hostIpAddress;
    }

    public LiveData<Boolean> getConnectionStatus() {
        return connectionStatus;
    }

    // ------------------- User Setup -------------------

    public void setUsername(String username) {
        repository.setUsername(username);
    }

    // ------------------- Network Controls -------------------

    public void hostChat() {
        repository.hostChat();
    }

    public void joinChat(String hostIp) {
        repository.joinChat(hostIp);
    }

    public void stopNetwork() {
        repository.stopNetwork();
    }

    // ------------------- Messaging Actions -------------------

    public void sendMessage(String text) {
        repository.sendMessage(text);
    }

    public void sendImageMessage(String filePath, String caption) {
        repository.sendImageMessage(filePath, caption);
    }

    public void sendDocumentMessage(String filePath, String fileName, long fileSize) {
        repository.sendDocumentMessage(filePath, fileName, fileSize);
    }

    // ------------------- Message Interaction -------------------

    public void likeMessage(int messageId, boolean isLiked) {
        // Handles both like and unlike depending on isLiked flag
        repository.likeMessage(messageId, isLiked);
    }

    public void editMessage(int messageId, String newText) {
        repository.editMessage(messageId, newText);
    }

    public void deleteMessage(int messageId) {
        repository.deleteMessage(messageId);
    }

    // ------------------- Lifecycle Cleanup -------------------

    @Override
    protected void onCleared() {
        super.onCleared();
        // Stop network threads and release any wake locks
        repository.stopNetwork();
    }
}
