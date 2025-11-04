package com.example.chitchatapp.db;

import androidx.room.Entity;
import androidx.room.Ignore;
import androidx.room.PrimaryKey;

@Entity(tableName = "messages")
public class Message {

    @PrimaryKey(autoGenerate = true)
    private int id;

    private String senderName;
    private String text;
    private long timestamp;
    private boolean isSentByUser;
    
    // Unique message identifier for network sync (sender + timestamp hash)
    private String uniqueId = null;
    
    // New fields for like, edit, delete functionality
    private int likeCount = 0;
    private String likedBy = null; // Comma-separated list of usernames who liked (e.g., "User1,User2")
    private boolean isEdited = false;
    private boolean isDeleted = false;
    private String editedText = null;
    
    // Media messaging fields
    private String messageType = "text"; // "text", "image", "document"
    private String filePath = null; // Local file path
    private String fileName = null; // Original file name
    private long fileSize = 0; // File size in bytes
    private String fileUri = null; // URI for file (for sharing)

    // Constructor with unique ID - Room will use this one
    public Message(String senderName, String text, long timestamp, boolean isSentByUser, String uniqueId) {
        this.senderName = senderName;
        this.text = text;
        this.timestamp = timestamp;
        this.isSentByUser = isSentByUser;
        this.uniqueId = uniqueId != null ? uniqueId : senderName + "_" + timestamp;
        this.likeCount = 0;
        this.likedBy = null;
        this.isEdited = false;
        this.isDeleted = false;
        this.editedText = null;
        this.messageType = "text";
        this.filePath = null;
        this.fileName = null;
        this.fileSize = 0;
        this.fileUri = null;
    }
    
    // Convenience constructor - ignored by Room
    @Ignore
    public Message(String senderName, String text, long timestamp, boolean isSentByUser) {
        this(senderName, text, timestamp, isSentByUser, null);
    }
    
    // Constructor for media messages - ignored by Room
    @Ignore
    public Message(String senderName, String text, long timestamp, boolean isSentByUser, 
                   String messageType, String filePath, String fileName, long fileSize) {
        this.senderName = senderName;
        this.text = text;
        this.timestamp = timestamp;
        this.isSentByUser = isSentByUser;
        this.uniqueId = senderName + "_" + timestamp;
        this.likeCount = 0;
        this.isEdited = false;
        this.isDeleted = false;
        this.editedText = null;
        this.messageType = messageType != null ? messageType : "text";
        this.filePath = filePath;
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.fileUri = null;
    }

    // --- Getters (CRITICAL for Room and Adapter) ---

    public int getId() {
        return id;
    }
    public void setSentByUser(boolean sentByUser) {
        this.isSentByUser = sentByUser;
    }


    public String getSenderName() {
        return senderName;
    }

    public String getText() {
        return text;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public boolean isSentByUser() {
        return isSentByUser;
    }

    // --- Setters ---

    public void setId(int id) {
        this.id = id;
    }

    public void setText(String text) {
        this.text = text;
    }

    public void setLikeCount(int likeCount) {
        this.likeCount = likeCount;
    }

    public void setIsEdited(boolean isEdited) {
        this.isEdited = isEdited;
    }

    public void setIsDeleted(boolean isDeleted) {
        this.isDeleted = isDeleted;
    }

    public void setEditedText(String editedText) {
        this.editedText = editedText;
    }

    // --- Getters for new fields ---

    public int getLikeCount() {
        return likeCount;
    }

    public boolean isEdited() {
        return isEdited;
    }

    public boolean isDeleted() {
        return isDeleted;
    }

    public String getEditedText() {
        return editedText;
    }
    
    public String getUniqueId() {
        return uniqueId;
    }
    
    public void setUniqueId(String uniqueId) {
        this.uniqueId = uniqueId;
    }
    
    public String getLikedBy() {
        return likedBy;
    }
    
    public void setLikedBy(String likedBy) {
        this.likedBy = likedBy;
    }
    
    // Helper to get list of users who liked
    public java.util.List<String> getLikedByList() {
        if (likedBy == null || likedBy.isEmpty()) {
            return new java.util.ArrayList<>();
        }
        java.util.List<String> list = new java.util.ArrayList<>();
        String[] users = likedBy.split(",");
        for (String user : users) {
            if (user != null && !user.trim().isEmpty()) {
                list.add(user.trim());
            }
        }
        return list;
    }
    
    // Getters for media fields
    public String getMessageType() {
        return messageType;
    }
    
    public String getFilePath() {
        return filePath;
    }
    
    public String getFileName() {
        return fileName;
    }
    
    public long getFileSize() {
        return fileSize;
    }
    
    public String getFileUri() {
        return fileUri;
    }
    
    // Setters for media fields
    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }
    
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }
    
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }
    
    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }
    
    public void setFileUri(String fileUri) {
        this.fileUri = fileUri;
    }
    
    // Helper method to get display text (original or edited)
    public String getDisplayText() {
        if (isDeleted) {
            return "This message was deleted";
        }
        return (isEdited && editedText != null) ? editedText : text;
    }
    
    // Helper to format file size
    public String getFormattedFileSize() {
        if (fileSize < 1024) {
            return fileSize + " B";
        } else if (fileSize < 1024 * 1024) {
            return String.format("%.1f KB", fileSize / 1024.0);
        } else {
            return String.format("%.1f MB", fileSize / (1024.0 * 1024.0));
        }
    }
}
