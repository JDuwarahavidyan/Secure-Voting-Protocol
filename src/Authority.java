import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class Authority {

    private final KeyPair authorityKeyPair;

    public Authority() throws Exception {
        this.authorityKeyPair = CryptoUtils.generateRSAKeyPair();
    }

    public PublicKey getAuthorityPublicKey() {
        return authorityKeyPair.getPublic();
    }

    public PrivateKey getAuthorityPrivateKey() {
        return authorityKeyPair.getPrivate();
    }

    // Simple Authority “certificate”
    public String getCertificate() {
        return "Authority Certificate: " + getAuthorityPublicKey().toString();
    }

    /**
     * Generate a token (nonce + timestamp), sign it, encrypt for voter.
     * Returns [signedToken, encryptedToken, plainToken] for demonstration.
     */
    public byte[][] issueToken(PublicKey voterPublicKey) throws Exception {
        // ✅ Generate fresh nonce
        String nonce = Nonce.generateNonce();

        // ✅ Add timestamp
        String timestamp = Instant.now().toString();

        // ✅ Token = nonce|timestamp
        String tokenData = nonce + "|" + timestamp;

        // ✅ Sign token with SHA256withRSA
        byte[] signedToken = CryptoUtils.signSHA256withRSA(tokenData.getBytes(), getAuthorityPrivateKey());

        // ✅ Encrypt token for voter
        byte[] encryptedToken = CryptoUtils.encryptRSA(signedToken, voterPublicKey);
       
        return new byte[][] {
            encryptedToken,
      
        };
    }
}
