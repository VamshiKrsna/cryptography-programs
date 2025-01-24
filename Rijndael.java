import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class Rijndael {
    public static void main(String[] args) throws Exception {
        String message = "AES still rocks!!";
        String input = args.length == 0 ? message : args[0];

        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit key
        Key secretKey = keyGen.generateKey();

        // Initialize cipher for encryption
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(input.getBytes());

        // Print encrypted message in hex
        System.out.println("Encrypted: " + bytesToHex(encrypted));

        // Initialize cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypted = cipher.doFinal(encrypted);

        // Print decrypted message
        System.out.println("Decrypted: " + new String(decrypted));
    }

    // Helper method to convert bytes to hex
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}