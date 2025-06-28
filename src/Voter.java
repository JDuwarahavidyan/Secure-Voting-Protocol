import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Voter {

    private final KeyPair keyPair;

    public Voter() throws Exception {
        this.keyPair = CryptoUtils.generateRSAKeyPair();
    }

    public PublicKey getVoterPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getVoterPrivateKey() {
        return keyPair.getPrivate();
    }

    /**
     * Verifies the token signature with the Authority's public key.
     */
    public boolean verifyToken(String tokenData, String signatureBase64, PublicKey authorityPubKey) throws Exception {
        byte[] signature = Base64.getDecoder().decode(signatureBase64);
        return CryptoUtils.verifySHA256withRSA(tokenData.getBytes(), signature, authorityPubKey);
    }
}
