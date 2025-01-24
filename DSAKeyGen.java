import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DSAKeyGen {
    public static void main(String[] args) throws Exception {
        // Generate a 1024-bit DSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Get the private and public keys
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Print the keys
        System.out.println("Private Key: " + privateKey);
        System.out.println("Public Key: " + publicKey);
    }
}