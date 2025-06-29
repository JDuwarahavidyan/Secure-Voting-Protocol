import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.SecretKey;

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

    public boolean verifyToken(String tokenData, String signatureBase64, PublicKey authorityPubKey) throws Exception {
        byte[] signature = Base64.getDecoder().decode(signatureBase64);
        return CryptoUtils.verifySHA256withRSA(tokenData.getBytes(), signature, authorityPubKey);
    }

     public String[] prepareVote(String vote, String tokenData, PublicKey authorityPubKey) throws Exception {
        // 1) Hash the vote
        String hashedVote = CryptoUtils.hashSHA256(vote);
        

        // 2) Generate AES key
        SecretKey symmetricKey = CryptoUtils.generateAESKey();

        // 3) Encrypt vote with AES
        byte[] encryptedVoteBytes = CryptoUtils.encryptAES(vote.getBytes(), symmetricKey);
        String encryptedVote = Base64.getEncoder().encodeToString(encryptedVoteBytes);

        // 4) Bundle { K | tokenData } as bytes
        byte[] kBytes = symmetricKey.getEncoded();
        byte[] tokenBytes = tokenData.getBytes();
        byte[] bundle = new byte[kBytes.length + tokenBytes.length];
        System.arraycopy(kBytes, 0, bundle, 0, kBytes.length);
        System.arraycopy(tokenBytes, 0, bundle, kBytes.length, tokenBytes.length);

        // 5) Encrypt bundle with Authority's public key
        byte[] encryptedBundle = CryptoUtils.encryptRSA(bundle, authorityPubKey);
        String encryptedTokenKey = Base64.getEncoder().encodeToString(encryptedBundle);

        return new String[] {
                hashedVote,
                encryptedVote,
                encryptedTokenKey
        };
    }
}
