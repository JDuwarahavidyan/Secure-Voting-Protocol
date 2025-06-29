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

         System.out.println("\n========== Voter: Prepare Vote ==========");
        // 1) Hash the vote
        String hashedVote = CryptoUtils.hashSHA256(vote);
        System.out.println("Hashed Vote: " + hashedVote + "\n");

        // 2) Generate AES key
        SecretKey symmetricKey = CryptoUtils.generateAESKey();
        byte[] kBytes = symmetricKey.getEncoded();
        String kBase64 = Base64.getEncoder().encodeToString(kBytes);
        System.out.println("Generated AES Key: " + kBase64 + "\n");

        // 3) Encrypt vote with AES
        byte[] encryptedVoteBytes = CryptoUtils.encryptAES(vote.getBytes(), symmetricKey);
        String encryptedVote = Base64.getEncoder().encodeToString(encryptedVoteBytes);
        System.out.println("Encrypted Vote with AES: " + encryptedVote + "\n");

        // 4) Bundle { K | tokenData } as bytes
        byte[] tokenBytes = tokenData.getBytes();
        byte[] bundle = new byte[kBytes.length + tokenBytes.length];
        System.arraycopy(kBytes, 0, bundle, 0, kBytes.length);
        System.arraycopy(tokenBytes, 0, bundle, kBytes.length, tokenBytes.length);

        // 5) Encrypt bundle with Authority's public key
        byte[] encryptedBundle = CryptoUtils.encryptRSA(bundle, authorityPubKey);
        String encryptedTokenKey = Base64.getEncoder().encodeToString(encryptedBundle);
        System.out.println("Encrypted Token + Key with Authority Pub Key: " + encryptedTokenKey + "\n");

        System.out.println("==========================================");

        return new String[] {
                hashedVote,
                encryptedVote,
                encryptedTokenKey
        };
    }
}
