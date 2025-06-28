import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Voter {

    private final KeyPair keyPair;

    public Voter() throws Exception {
        this.keyPair = CryptoUtils.generateRSAKeyPair();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    /**
     * Voter decrypts received token.
     */
    public String decryptToken(byte[] encryptedToken) throws Exception {
        byte[] decryptedBytes = CryptoUtils.decryptRSA(encryptedToken, getPrivateKey());
        return new String(decryptedBytes);
    }

    /**
     * Voter verifies Authority’s signature.
     */
    public boolean verifyTokenSignature(String tokenData, byte[] signature, PublicKey authorityPublicKey) throws Exception {
        return CryptoUtils.verifySHA256withRSA(tokenData.getBytes(), signature, authorityPublicKey);
    }
}
