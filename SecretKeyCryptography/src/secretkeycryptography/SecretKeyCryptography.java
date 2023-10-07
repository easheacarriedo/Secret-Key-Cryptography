package cryptography;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 * This class provides methods for secret key cryptography using AES algorithm.
 */
public class SecretKeyCryptography {

    /**
     * Generates a secret key using AES algorithm.
     *
     * @return Returns the generated secret key.
     * @throws NoSuchAlgorithmException if the AES algorithm is not available.
     */
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // 128-bit key size
        return keyGenerator.generateKey();
    }

    /**
     * Encrypts the given plaintext using the provided secret key.
     *
     * @param plaintext The plaintext to be encrypted.
     * @param secretKey The secret key used for encryption.
     * @return Returns the encrypted ciphertext.
     * @throws Exception if an error occurs during encryption.
     */
    public static byte[] encrypt(byte[] plaintext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext);
    }

    /**
     * Decrypts the given ciphertext using the provided secret key.
     *
     * @param ciphertext The ciphertext to be decrypted.
     * @param secretKey The secret key used for decryption.
     * @return Returns the decrypted plaintext.
     * @throws Exception if an error occurs during decryption.
     */
    public static byte[] decrypt(byte[] ciphertext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Main method to demonstrate the usage of secret key cryptography.
     *
     * @param args Command line arguments (not used).
     */
    public static void main(String[] args) {
        try {
            // Generate a secret key
            SecretKey secretKey = generateSecretKey();

            // Encrypt a plaintext
            String plaintext = "This is a secret message.";
            byte[] encrypted = encrypt(plaintext.getBytes(), secretKey);
            System.out.println("Encrypted ciphertext: " + new String(encrypted));

            // Decrypt the ciphertext
            byte[] decrypted = decrypt(encrypted, secretKey);
            System.out.println("Decrypted plaintext: " + new String(decrypted));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

