package com.example.chitchatapp.db; // Updated

import androidx.lifecycle.LiveData;
import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

import java.util.List;

@Dao
public interface MessageDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insertMessage(Message message);

    @Query("SELECT * FROM messages ORDER BY timestamp ASC")
    LiveData<List<Message>> getAllMessages();

    @Query("UPDATE messages SET likeCount = likeCount + 1 WHERE uniqueId = :uniqueId")
    void incrementLike(String uniqueId);

    @Query("UPDATE messages SET likeCount = CASE WHEN likeCount > 0 THEN likeCount - 1 ELSE 0 END WHERE uniqueId = :uniqueId")
    void decrementLike(String uniqueId);
    
    @Query("UPDATE messages SET likedBy = :likedBy WHERE uniqueId = :uniqueId")
    void updateLikedBy(String uniqueId, String likedBy);
    
    @Query("SELECT likedBy FROM messages WHERE uniqueId = :uniqueId")
    String getLikedBy(String uniqueId);

    @Query("UPDATE messages SET text = :newText, isEdited = 1, editedText = :newText WHERE uniqueId = :uniqueId")
    void updateMessage(String uniqueId, String newText);

    @Query("UPDATE messages SET isDeleted = 1 WHERE uniqueId = :uniqueId")
    void deleteMessage(String uniqueId);

    @Query("SELECT * FROM messages WHERE id = :messageId")
    Message getMessageById(int messageId);
    
    @Query("SELECT * FROM messages WHERE uniqueId = :uniqueId")
    Message getMessageByUniqueId(String uniqueId);

    @Query("DELETE FROM messages")
    void nukeTable(); // For clearing chat history
}
