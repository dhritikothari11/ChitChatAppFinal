package com.example.chitchatapp.adapter;

import android.app.AlertDialog;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.view.GestureDetector;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.DiffUtil;
import androidx.recyclerview.widget.ListAdapter;
import androidx.recyclerview.widget.RecyclerView;

import com.example.chitchatapp.R;
import com.example.chitchatapp.db.Message;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Locale;

public class ChatAdapter extends ListAdapter<Message, RecyclerView.ViewHolder> {

    private static final int VIEW_TYPE_SENT = 1;
    private static final int VIEW_TYPE_RECEIVED = 2;
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("h:mm a", Locale.getDefault());

    public interface MessageActionListener {
        void onLikeClicked(int messageId, boolean isLiked);
        void onEditClicked(int messageId, String currentText);
        void onDeleteClicked(int messageId);
        void onImageClicked(String filePath);
        void onDocumentClicked(String filePath, String fileName);
        void onLikesViewClicked(int messageId, java.util.List<String> likedByList);
    }

    private MessageActionListener actionListener;

    public ChatAdapter() {
        super(DIFF_CALLBACK);
    }

    public void setActionListener(MessageActionListener listener) {
        this.actionListener = listener;
    }

    // --- Gesture Listener ---
    private static class MessageGestureListener extends GestureDetector.SimpleOnGestureListener {
        private final View itemView;
        private final Message message;
        private final MessageActionListener listener;

        private static long lastDoubleTapTime = 0;
        private static int lastDoubleTapMessageId = -1;
        private static final long DOUBLE_TAP_DEBOUNCE = 400;

        MessageGestureListener(View itemView, Message message, MessageActionListener listener) {
            this.itemView = itemView;
            this.message = message;
            this.listener = listener;
        }

        @Override
        public boolean onDoubleTap(MotionEvent e) {
            long currentTime = System.currentTimeMillis();
            int messageId = message.getId();

            if (messageId == lastDoubleTapMessageId &&
                    currentTime - lastDoubleTapTime < DOUBLE_TAP_DEBOUNCE) {
                return true;
            }

            lastDoubleTapMessageId = messageId;
            lastDoubleTapTime = currentTime;

            if (listener != null && !message.isDeleted()) {
                listener.onLikeClicked(message.getId(), true);
            }
            return true;
        }

        @Override
        public void onLongPress(MotionEvent e) {
            // Allow edit only for own text messages
            if (listener == null || !message.isSentByUser() || message.isDeleted()) return;

            if ("text".equals(message.getMessageType())) {
                new AlertDialog.Builder(itemView.getContext())
                        .setTitle("Edit Message")
                        .setMessage("Do you want to edit this message?")
                        .setPositiveButton("Edit", (dialog, which) -> {
                            listener.onEditClicked(message.getId(), message.getDisplayText());
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
            }
        }
    }

    @Override
    public int getItemViewType(int position) {
        Message message = getItem(position);
        return (message != null && message.isSentByUser()) ? VIEW_TYPE_SENT : VIEW_TYPE_RECEIVED;
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        if (viewType == VIEW_TYPE_SENT) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_message_sent, parent, false);
            return new SentMessageHolder(view);
        } else {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_message_received, parent, false);
            return new ReceivedMessageHolder(view);
        }
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        Message message = getItem(position);
        if (message == null) return;

        if (holder.getItemViewType() == VIEW_TYPE_SENT) {
            ((SentMessageHolder) holder).bind(message);
        } else {
            ((ReceivedMessageHolder) holder).bind(message);
        }
    }

    // --- Sent Messages ---
    private class SentMessageHolder extends RecyclerView.ViewHolder {
        TextView messageText, timeText, editedText;
        ImageView likeIndicator, imagePreview;
        ImageButton deleteButton;
        View documentPreview;
        TextView documentName, documentSize;
        GestureDetector gestureDetector;
        View bubbleContainer;

        SentMessageHolder(View itemView) {
            super(itemView);
            bubbleContainer = itemView.findViewById(R.id.chat_bubble_sent_container);
            messageText = itemView.findViewById(R.id.text_message_body);
            timeText = itemView.findViewById(R.id.text_message_timestamp);
            likeIndicator = itemView.findViewById(R.id.like_indicator);
            editedText = itemView.findViewById(R.id.text_edited);
            deleteButton = itemView.findViewById(R.id.button_delete);
            imagePreview = itemView.findViewById(R.id.image_preview);
            documentPreview = itemView.findViewById(R.id.document_preview);
            documentName = itemView.findViewById(R.id.document_name);
            documentSize = itemView.findViewById(R.id.document_size);
        }

        void bind(Message message) {
            messageText.setText(message.getDisplayText());
            messageText.setAlpha(message.isDeleted() ? 0.5f : 1.0f);
            timeText.setText(timeFormat.format(message.getTimestamp()));

            if (message.isEdited()) {
                editedText.setVisibility(View.VISIBLE);
            } else {
                editedText.setVisibility(View.GONE);
            }

            // ❤️ Handle likes
            int likes = message.getLikeCount();
            if (likes > 0) {
                likeIndicator.setVisibility(View.VISIBLE);
                likeIndicator.setOnClickListener(v -> {
                    if (actionListener != null) {
                        java.util.List<String> likedByList = message.getLikedByList();
                        actionListener.onLikesViewClicked(message.getId(), likedByList);
                    }
                });
            } else {
                likeIndicator.setVisibility(View.GONE);
            }

            // 📎 Handle media
            if ("image".equals(message.getMessageType()) && message.getFilePath() != null) {
                imagePreview.setVisibility(View.VISIBLE);
                documentPreview.setVisibility(View.GONE);
                loadImage(imagePreview, message.getFilePath());
                imagePreview.setOnClickListener(v -> {
                    if (actionListener != null)
                        actionListener.onImageClicked(message.getFilePath());
                });
            } else if ("document".equals(message.getMessageType()) && message.getFileName() != null) {
                imagePreview.setVisibility(View.GONE);
                documentPreview.setVisibility(View.VISIBLE);
                documentName.setText(message.getFileName());
                documentSize.setText(message.getFormattedFileSize());
                documentPreview.setOnClickListener(v -> {
                    if (actionListener != null)
                        actionListener.onDocumentClicked(message.getFilePath(), message.getFileName());
                });
            } else {
                imagePreview.setVisibility(View.GONE);
                documentPreview.setVisibility(View.GONE);
            }

            // 🗑️ Delete button for own messages
            if (message.isSentByUser() && !message.isDeleted()) {
                deleteButton.setVisibility(View.VISIBLE);
                deleteButton.setOnClickListener(v -> {
                    if (actionListener != null)
                        actionListener.onDeleteClicked(message.getId());
                });
            } else {
                deleteButton.setVisibility(View.GONE);
            }

            gestureDetector = new GestureDetector(itemView.getContext(),
                    new MessageGestureListener(bubbleContainer, message, actionListener));

            bubbleContainer.setOnTouchListener((v, event) -> {
                gestureDetector.onTouchEvent(event);
                return true;
            });
        }

        private void loadImage(ImageView imageView, String filePath) {
            try {
                File imgFile = new File(filePath);
                if (imgFile.exists()) {
                    Bitmap bitmap = BitmapFactory.decodeFile(imgFile.getAbsolutePath());
                    imageView.setImageBitmap(bitmap);
                }
            } catch (Exception ignored) {
            }
        }
    }

    // --- Received Messages ---
    private class ReceivedMessageHolder extends RecyclerView.ViewHolder {
        TextView messageText, timeText, senderNameText, editedText;
        ImageView likeIndicator, imagePreview;
        View documentPreview;
        TextView documentName, documentSize;
        GestureDetector gestureDetector;
        View bubbleContainer;

        ReceivedMessageHolder(View itemView) {
            super(itemView);
            bubbleContainer = itemView.findViewById(R.id.chat_bubble_received_container);
            messageText = itemView.findViewById(R.id.text_message_body);
            timeText = itemView.findViewById(R.id.text_message_timestamp);
            senderNameText = itemView.findViewById(R.id.text_message_name);
            likeIndicator = itemView.findViewById(R.id.like_indicator);
            editedText = itemView.findViewById(R.id.text_edited);
            imagePreview = itemView.findViewById(R.id.image_preview);
            documentPreview = itemView.findViewById(R.id.document_preview);
            documentName = itemView.findViewById(R.id.document_name);
            documentSize = itemView.findViewById(R.id.document_size);
        }

        void bind(Message message) {
            messageText.setText(message.getDisplayText());
            messageText.setAlpha(message.isDeleted() ? 0.5f : 1.0f);
            timeText.setText(timeFormat.format(message.getTimestamp()));
            senderNameText.setText(message.getSenderName());

            if (message.isEdited()) {
                editedText.setVisibility(View.VISIBLE);
            } else {
                editedText.setVisibility(View.GONE);
            }

            // ❤️ Handle likes
            int likes = message.getLikeCount();
            if (likes > 0) {
                likeIndicator.setVisibility(View.VISIBLE);
                likeIndicator.setOnClickListener(v -> {
                    if (actionListener != null) {
                        java.util.List<String> likedByList = message.getLikedByList();
                        actionListener.onLikesViewClicked(message.getId(), likedByList);
                    }
                });
            } else {
                likeIndicator.setVisibility(View.GONE);
            }

            // 📎 Handle media
            if ("image".equals(message.getMessageType()) && message.getFilePath() != null) {
                imagePreview.setVisibility(View.VISIBLE);
                documentPreview.setVisibility(View.GONE);
                loadImage(imagePreview, message.getFilePath());
                imagePreview.setOnClickListener(v -> {
                    if (actionListener != null)
                        actionListener.onImageClicked(message.getFilePath());
                });
            } else if ("document".equals(message.getMessageType()) && message.getFileName() != null) {
                imagePreview.setVisibility(View.GONE);
                documentPreview.setVisibility(View.VISIBLE);
                documentName.setText(message.getFileName());
                documentSize.setText(message.getFormattedFileSize());
                documentPreview.setOnClickListener(v -> {
                    if (actionListener != null)
                        actionListener.onDocumentClicked(message.getFilePath(), message.getFileName());
                });
            } else {
                imagePreview.setVisibility(View.GONE);
                documentPreview.setVisibility(View.GONE);
            }

            gestureDetector = new GestureDetector(itemView.getContext(),
                    new MessageGestureListener(bubbleContainer, message, actionListener));

            bubbleContainer.setOnTouchListener((v, event) -> {
                gestureDetector.onTouchEvent(event);
                return true;
            });
        }

        private void loadImage(ImageView imageView, String filePath) {
            try {
                File imgFile = new File(filePath);
                if (imgFile.exists()) {
                    Bitmap bitmap = BitmapFactory.decodeFile(imgFile.getAbsolutePath());
                    imageView.setImageBitmap(bitmap);
                }
            } catch (Exception ignored) {
            }
        }
    }

    // --- DiffUtil for Efficient Updates ---
    private static final DiffUtil.ItemCallback<Message> DIFF_CALLBACK = new DiffUtil.ItemCallback<Message>() {
        @Override
        public boolean areItemsTheSame(@NonNull Message oldItem, @NonNull Message newItem) {
            return oldItem.getId() == newItem.getId();
        }

        @Override
        public boolean areContentsTheSame(@NonNull Message oldItem, @NonNull Message newItem) {
            return oldItem.getText().equals(newItem.getText()) &&
                    oldItem.getTimestamp() == newItem.getTimestamp() &&
                    oldItem.isSentByUser() == newItem.isSentByUser() &&
                    oldItem.getLikeCount() == newItem.getLikeCount() &&
                    oldItem.isEdited() == newItem.isEdited() &&
                    oldItem.isDeleted() == newItem.isDeleted() &&
                    java.util.Objects.equals(oldItem.getMessageType(), newItem.getMessageType()) &&
                    java.util.Objects.equals(oldItem.getFilePath(), newItem.getFilePath());
        }
    };
}
