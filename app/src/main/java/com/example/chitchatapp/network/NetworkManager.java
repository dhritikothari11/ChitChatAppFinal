

package com.example.chitchatapp.network;

import android.content.Context;
import android.net.wifi.WifiManager;
import android.os.PowerManager;
import android.text.format.Formatter;
import android.util.Log;
import android.widget.Toast;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import com.example.chitchatapp.utils.EncryptionUtil;

public class NetworkManager {

    private static final String TAG = "NetworkManager";
    private static final int PORT = 12345;

    private final ExecutorService executor = Executors.newCachedThreadPool();
    private ServerSocket serverSocket;
    private final List<PrintWriter> clientWriters = Collections.synchronizedList(new ArrayList<>());

    private String hostUsername = "Host";
    private Socket clientSocket;
    private volatile PrintWriter clientWriter;
    private BufferedReader clientReader;

    private final MessageReceiver messageReceiver;
    private final MutableLiveData<String> hostIpAddress = new MutableLiveData<>();
    private final MutableLiveData<Boolean> connectionStatus = new MutableLiveData<>();
    private final Context context;

    private PowerManager.WakeLock wakeLock;
    private WifiManager.WifiLock wifiLock;

    // ===============================================================
    // Interface for callbacks to ChatRepository
    // ===============================================================
    public interface MessageReceiver {
        void onMessageReceived(String sender, String text);
        void onMessageLiked(String uniqueId, boolean isLiked);
        void onMessageEdited(String uniqueId, String newText);
        void onMessageDeleted(String uniqueId);
        void onImageReceived(String uniqueId, String caption, String base64Data);
        void onDocumentReceived(String uniqueId, String fileName, long fileSize, String base64Data);
    }

    // ===============================================================
    public NetworkManager(Context context, MessageReceiver receiver) {
        this.context = context.getApplicationContext();
        this.messageReceiver = receiver;
        initializeLocks();
    }

    private void initializeLocks() {
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "ChitChatApp::CpuWakeLock");
        WifiManager wm = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "ChitChatApp::WifiWakeLock");
    }

    private void acquireLocks() {
        if (!wakeLock.isHeld()) wakeLock.acquire();
        if (!wifiLock.isHeld()) wifiLock.acquire();
    }

    private void releaseLocks() {
        if (wakeLock.isHeld()) wakeLock.release();
        if (wifiLock.isHeld()) wifiLock.release();
    }

    public LiveData<String> getHostIpAddress() { return hostIpAddress; }
    public LiveData<Boolean> getConnectionStatus() { return connectionStatus; }

    // ===============================================================
    // HOST MODE
    // ===============================================================
    public void startHost(String username) {
        this.hostUsername = (username != null && !username.isEmpty()) ? username : "Host";
        executor.execute(() -> {
            try {
                String ip = getLocalIpAddress();
                if (ip == null) throw new IOException("Unable to get Wi-Fi IP address. Are you connected?");
                acquireLocks();

                serverSocket = new ServerSocket(PORT);
                hostIpAddress.postValue("Hosting on: " + ip);
                connectionStatus.postValue(true);
                Log.d(TAG, "Server started on IP: " + ip);

                while (!Thread.currentThread().isInterrupted()) {
                    Socket client = serverSocket.accept();
                    client.setTcpNoDelay(true);
                    handleClient(client);
                }
            } catch (IOException e) {
                Log.e(TAG, "Host error", e);
                hostIpAddress.postValue("Host failed: " + e.getMessage());
                connectionStatus.postValue(false);
                releaseLocks();
            }
        });
    }

    private void handleClient(Socket clientSocket) {
        executor.execute(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true)) {

                String username = reader.readLine();
                if (username == null || username.isEmpty())
                    username = "Guest-" + System.currentTimeMillis() % 1000;

                clientWriters.add(writer);

                // ENCRYPT join message for network, send UNENCRYPTED to local UI
                String joinMsgEncrypted = EncryptionUtil.encrypt("has joined the chat.");
                if (joinMsgEncrypted != null) {
                    broadcastMessage(username, joinMsgEncrypted);
                }
                messageReceiver.onMessageReceived(username, "has joined the chat.");

                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.trim().isEmpty()) continue;

                    // Decrypt the received line
                    String decryptedLine = EncryptionUtil.decrypt(line);
                    if (decryptedLine == null) {
                        Log.e(TAG, "Failed to decrypt message from client.");
                        continue;
                    }

                    Log.d(TAG, "Host received: " +
                            (decryptedLine.length() > 120 ? decryptedLine.substring(0, 120) + "..." : decryptedLine));

                    if (decryptedLine.startsWith("LIKE:") || decryptedLine.startsWith("UNLIKE:")
                            || decryptedLine.startsWith("EDIT:") || decryptedLine.startsWith("DELETE:")) {
                        broadcastCommand(line); // Broadcast ENCRYPTED line to other clients
                        processCommand(decryptedLine); // Process DECRYPTED line locally
                        continue;
                    }

                    // Images (no username prefix)
                    if (decryptedLine.startsWith("IMG:")) {
                        broadcastRaw(line); // Broadcast ENCRYPTED line
                        String[] parts = decryptedLine.split(":", 4);
                        if (parts.length == 4)
                            messageReceiver.onImageReceived(parts[1], parts[2], parts[3]);
                        continue;
                    }

                    // Documents (no username prefix)
                    if (decryptedLine.startsWith("DOC:")) {
                        broadcastRaw(line); // Broadcast ENCRYPTED line
                        String[] parts = decryptedLine.split(":", 5);
                        if (parts.length == 5) {
                            try {
                                long size = Long.parseLong(parts[3]);
                                messageReceiver.onDocumentReceived(parts[1], parts[2], size, parts[4]);
                            } catch (Exception e) {
                                Log.e(TAG, "Host DOC parse error", e);
                            }
                        }
                        continue;
                    }

                    // Normal chat text
                    broadcastMessage(username, line); // Broadcast ENCRYPTED line with username
                    messageReceiver.onMessageReceived(username, decryptedLine); // Process DECRYPTED line
                }

            } catch (Exception e) {
                Log.e(TAG, "Client handler error", e);
            } finally {
                Log.d(TAG, "Client disconnected");
            }
        });
    }

    // ===============================================================
    // CLIENT MODE
    // ===============================================================
    public void startClient(String hostIp, String username) {
        executor.execute(() -> {
            try {
                acquireLocks();
                clientSocket = new Socket(hostIp, PORT);
                clientSocket.setTcpNoDelay(true);
                clientWriter = new PrintWriter(clientSocket.getOutputStream(), true);
                clientReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                clientWriter.println(username);
                clientWriter.flush();
                connectionStatus.postValue(true);
                Log.d(TAG, "Client connected to host " + hostIp);

                String line;
                while ((line = clientReader.readLine()) != null) {
                    if (line.trim().isEmpty()) continue;

                    // Decrypt the received line
                    String decryptedLine = EncryptionUtil.decrypt(line);
                    if (decryptedLine == null) {
                        Log.e(TAG, "Failed to decrypt message from host.");
                        continue;
                    }

                    Log.d(TAG, "Client received: " +
                            (decryptedLine.length() > 120 ? decryptedLine.substring(0, 120) + "..." : decryptedLine));

                    if (decryptedLine.startsWith("LIKE:")) { messageReceiver.onMessageLiked(decryptedLine.substring(5), true); continue; }
                    if (decryptedLine.startsWith("UNLIKE:")) { messageReceiver.onMessageLiked(decryptedLine.substring(7), false); continue; }

                    if (decryptedLine.startsWith("EDIT:")) {
                        String[] parts = decryptedLine.substring(5).split(":", 2);
                        if (parts.length == 2) messageReceiver.onMessageEdited(parts[0], parts[1]);
                        continue;
                    }

                    if (decryptedLine.startsWith("DELETE:")) { messageReceiver.onMessageDeleted(decryptedLine.substring(7)); continue; }

                    // Image
                    if (decryptedLine.startsWith("IMG:")) {
                        String[] parts = decryptedLine.split(":", 4);
                        if (parts.length == 4)
                            messageReceiver.onImageReceived(parts[1], parts[2], parts[3]);
                        continue;
                    }

                    // Document
                    if (decryptedLine.startsWith("DOC:")) {
                        String[] parts = decryptedLine.split(":", 5);
                        if (parts.length == 5) {
                            try {
                                long size = Long.parseLong(parts[3]);
                                messageReceiver.onDocumentReceived(parts[1], parts[2], size, parts[4]);
                            } catch (Exception e) {
                                Log.e(TAG, "Client DOC parse error", e);
                            }
                        }
                        continue;
                    }

                    // Regular message
                    if (decryptedLine.contains(": ")) {
                        String[] parts = decryptedLine.split(": ", 2);
                        if (parts.length == 2) messageReceiver.onMessageReceived(parts[0], parts[1]);
                    }
                }

            } catch (Exception e) {
                Log.e(TAG, "Client connection error", e);
                connectionStatus.postValue(false);
                releaseLocks();
                new android.os.Handler(context.getMainLooper()).post(() ->
                        Toast.makeText(context, "Connection failed. Check IP and Wi-Fi.", Toast.LENGTH_LONG).show());
            }
        });
    }

    // ===============================================================
    // MESSAGE SENDER
    // ===============================================================
    public void sendMessage(String message) {
        executor.execute(() -> {
            try {
                // Encrypt the message before sending
                String encryptedMessage = EncryptionUtil.encrypt(message);
                if (encryptedMessage == null) {
                    Log.e(TAG, "Failed to encrypt message.");
                    return;
                }

                if (serverSocket != null && !serverSocket.isClosed()) {
                    // 🔥 Important: send images/docs as raw (no "username:")
                    if (message.startsWith("IMG:") || message.startsWith("DOC:")) {
                        // Host sending image/doc (raw)
                        broadcastRaw(encryptedMessage);
                    } else {
                        // Host sending normal text
                        broadcastMessage(hostUsername, encryptedMessage);
                    }
                    // Handle locally for the Host's UI (must use unencrypted message for UI update)
                    if (message.startsWith("IMG:")) {
                        String[] parts = message.split(":", 4);
                        if (parts.length == 4) messageReceiver.onImageReceived(parts[1], parts[2], parts[3]);
                    } else if (message.startsWith("DOC:")) {
                        String[] parts = message.split(":", 5);
                        if (parts.length == 5) {
                            try {
                                long size = Long.parseLong(parts[3]);
                                messageReceiver.onDocumentReceived(parts[1], parts[2], size, parts[4]);
                            } catch (Exception e) {
                                Log.e(TAG, "Host DOC send error", e);
                            }
                        }
                    } else {
                        messageReceiver.onMessageReceived(hostUsername, message);
                    }
                } else if (clientWriter != null) {
                    // Client sending message
                    clientWriter.println(encryptedMessage);
                    clientWriter.flush();
                }
            } catch (Exception e) {
                Log.e(TAG, "Error sending message", e);
            }
        });
    }

    public void sendLike(String uniqueId, boolean isLiked) {
        sendCommand((isLiked ? "LIKE:" : "UNLIKE:") + uniqueId);
    }

    public void sendEdit(String uniqueId, String newText) {
        sendCommand("EDIT:" + uniqueId + ":" + newText);
    }

    public void sendDelete(String uniqueId) {
        sendCommand("DELETE:" + uniqueId);
    }

    private void sendCommand(String command) {
        executor.execute(() -> {
            // Encrypt the command too, as it's sensitive
            String encryptedCommand = EncryptionUtil.encrypt(command);
            if (encryptedCommand == null) {
                Log.e(TAG, "Failed to encrypt command.");
                return;
            }

            if (serverSocket != null && !serverSocket.isClosed()) {
                // Host sending: broadcast the encrypted command
                broadcastCommand(encryptedCommand);
                processCommand(command); // Process the UNENCRYPTED command locally
            } else if (clientWriter != null) {
                // Client sending: send the encrypted command to the host
                clientWriter.println(encryptedCommand);
                clientWriter.flush();
            }
        });
    }

    // ===============================================================
    // BROADCAST HELPERS
    // ===============================================================
    // The message parameter is now expected to be the ENCRYPTED content.
    private void broadcastMessage(String sender, String encryptedMessage) {
        synchronized (clientWriters) {
            for (PrintWriter w : new ArrayList<>(clientWriters)) {
                try {
                    // Prepend sender's name to the encrypted message
                    w.println(sender + ": " + encryptedMessage);
                    w.flush();
                } catch (Exception e) {
                    clientWriters.remove(w);
                }
            }
        }
    }

    // The command parameter is now expected to be the ENCRYPTED command.
    private void broadcastCommand(String encryptedCommand) {
        synchronized (clientWriters) {
            for (PrintWriter w : new ArrayList<>(clientWriters)) {
                try {
                    w.println(encryptedCommand);
                    w.flush();
                } catch (Exception e) {
                    clientWriters.remove(w);
                }
            }
        }
    }

    // The message parameter is now expected to be the ENCRYPTED raw data (IMG/DOC).
    private void broadcastRaw(String encryptedMessage) {
        synchronized (clientWriters) {
            for (PrintWriter w : new ArrayList<>(clientWriters)) {
                try {
                    w.println(encryptedMessage);
                    w.flush();
                } catch (Exception e) {
                    clientWriters.remove(w);
                }
            }
        }
    }

    // cmd parameter is expected to be the DECRYPTED command when called from the Host's receiver or sender.
    private void processCommand(String cmd) {
        try {
            if (cmd.startsWith("LIKE:"))
                messageReceiver.onMessageLiked(cmd.substring(5), true);
            else if (cmd.startsWith("UNLIKE:"))
                messageReceiver.onMessageLiked(cmd.substring(7), false);
            else if (cmd.startsWith("EDIT:")) {
                String[] parts = cmd.substring(5).split(":", 2);
                if (parts.length == 2) messageReceiver.onMessageEdited(parts[0], parts[1]);
            } else if (cmd.startsWith("DELETE:"))
                messageReceiver.onMessageDeleted(cmd.substring(7));
        } catch (Exception e) {
            Log.e(TAG, "Command parse failed: " + cmd, e);
        }
    }

    // ===============================================================
    // STOP & IP
    // ===============================================================
    public void stop() {
        executor.execute(() -> {
            try {
                if (serverSocket != null) serverSocket.close();
                if (clientSocket != null) clientSocket.close();
                for (PrintWriter w : clientWriters) w.close();
                clientWriters.clear();
                if (clientWriter != null) clientWriter.close();
                if (clientReader != null) clientReader.close();
            } catch (Exception e) {
                Log.e(TAG, "Error closing sockets", e);
            } finally {
                releaseLocks();
            }
        });
    }

    private String getLocalIpAddress() {
        try {
            WifiManager wm = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                int ip = wm.getConnectionInfo().getIpAddress();
                if (ip == 0) return null;
                return Formatter.formatIpAddress(ip);
            }
        } catch (Exception e) {
            Log.e(TAG, "IP fetch error", e);
        }
        return null;
    }
}