import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class DiffieHellman {
    private static final int BIT_LENGTH = 512; // Key size in bits
    private static final SecureRandom rnd = new SecureRandom();

    public static void main(String[] args) throws Exception {
        // Generate large prime numbers p and g
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH, rnd);
        BigInteger g = BigInteger.probablePrime(BIT_LENGTH, rnd);

        // Generate key pairs for both parties
        KeyPair keyPairA = createKeyPair(p, g);
        KeyPair keyPairB = createKeyPair(p, g);

        // Display public keys
        System.out.println("Public key A: " + keyPairA.getPublic());
        System.out.println("Public key B: " + keyPairB.getPublic());
    }

    private static KeyPair createKeyPair(BigInteger p, BigInteger g) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
        DHParameterSpec param = new DHParameterSpec(p, g);
        kpg.initialize(param);
        return kpg.generateKeyPair();
    }
}
