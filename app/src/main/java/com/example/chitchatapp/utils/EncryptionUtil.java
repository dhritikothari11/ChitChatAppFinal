package com.example.chitchatapp.utils;

import android.util.Base64;
import android.util.Log;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class EncryptionUtil {

    private static final String TAG = "EncryptionUtil";
    
    // NOTE: This key is hardcoded. Use Android Keystore for real security.
    private static final String SECRET_KEY = "YourSectetKey001"; // Must be exactly 16 characters
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String IV_STRING = "0123456789abcdef"; // Must be exactly 16 characters

    private static SecretKeySpec secretKeySpec;
    private static IvParameterSpec ivParameterSpec;

    static {
        try {
            secretKeySpec = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");
            ivParameterSpec = new IvParameterSpec(IV_STRING.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize key and IV", e);
        }
    }

    public static String encrypt(String strToEncrypt) {
        try {
            if (secretKeySpec == null) return strToEncrypt;

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            
            byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));
            String encryptedString = Base64.encodeToString(encryptedBytes, Base64.DEFAULT);

            // LOG for Encryption
            Log.d(TAG, "Encrypt Success | Original: " + 
                (strToEncrypt.length() > 50 ? strToEncrypt.substring(0, 50) + "..." : strToEncrypt) + 
                " | Cipher: " + encryptedString.substring(0, Math.min(encryptedString.length(), 50)) + "...");

            return encryptedString;

        } catch (Exception e) {
            Log.e(TAG, "Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt) {
        try {
            if (secretKeySpec == null) return strToDecrypt;

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            
            byte[] decodedBytes = Base64.decode(strToDecrypt, Base64.DEFAULT);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);

            String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

            // LOG for Decryption
            Log.d(TAG, "Decrypt Success | Cipher: " + 
                (strToDecrypt.length() > 50 ? strToDecrypt.substring(0, 50) + "..." : strToDecrypt) +
                " | Decrypted: " + decryptedString.substring(0, Math.min(decryptedString.length(), 50)) + "...");

            return decryptedString;

        } catch (Exception e) {
            Log.e(TAG, "Error while decrypting: " + e.toString());
        }
        return null;
    }
}