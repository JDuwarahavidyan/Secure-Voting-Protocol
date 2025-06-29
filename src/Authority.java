import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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

    public String getCertificate() {
        return Base64.getEncoder().encodeToString(getAuthorityPublicKey().getEncoded());
    }

    
    // Issue a new token with Sri Lanka local timestamp.
     
    public String[] issueToken() throws Exception {
        String nonce = Nonce.generateNonce();
        String timestamp = ZonedDateTime.now(ZoneId.of("Asia/Colombo")).toString();
        String tokenData = nonce + "|" + timestamp;

        byte[] signature = CryptoUtils.signSHA256withRSA(tokenData.getBytes(), getAuthorityPrivateKey());
        String signedToken = Base64.getEncoder().encodeToString(signature);

        saveTokenToCSV(tokenData, signedToken);

        return new String[]{
            tokenData,
            signedToken,
            getCertificate()
        };
    }

    
    // Save tokenData + signature to CSV.
     
    public void saveTokenToCSV(String tokenData, String signatureBase64) throws IOException {
        String filePath = "issued_tokens.csv";
        FileWriter csvWriter = new FileWriter(filePath, true);
        csvWriter.append(tokenData)
                .append(",")
                .append(signatureBase64)
                .append(",0\n");
        csvWriter.flush();
        csvWriter.close();
    }

    
    // Verify token signature, check expiry, mark as used.
     
    public boolean verifyVoteToken(String incomingTokenData, String incomingSignature) throws Exception {
        String filePath = "issued_tokens.csv";
        boolean found = false;

        BufferedReader csvReader = new BufferedReader(new FileReader(filePath));
        String row;
        while ((row = csvReader.readLine()) != null) {
            String[] parts = row.split(",");
            String storedTokenData = parts[0];
            String storedSignature = parts[1];
            String usedFlag = parts[2];

            if (storedTokenData.equals(incomingTokenData)
                    && storedSignature.equals(incomingSignature)) {

                found = true;

                if (usedFlag.equals("1")) {
                    System.out.println("Token already used!");
                    csvReader.close();
                    return false;
                }

                // Extract timestamp, parse as Sri Lanka time
                String[] tokenParts = storedTokenData.split("\\|");
                String timestampStr = tokenParts[1];
                ZonedDateTime tokenTime = ZonedDateTime.parse(timestampStr);
                ZonedDateTime now = ZonedDateTime.now(ZoneId.of("Asia/Colombo"));

                Duration age = Duration.between(tokenTime, now);
                if (age.toMinutes() > 5) {
                    System.out.println("Token expired! Older than 5 minutes.");
                    csvReader.close();
                    return false;
                }

                boolean valid = CryptoUtils.verifySHA256withRSA(
                        storedTokenData.getBytes(),
                        Base64.getDecoder().decode(storedSignature),
                        getAuthorityPublicKey()
                );

                csvReader.close();

                if (valid) {
                    markTokenAsUsed(incomingTokenData, incomingSignature);
                    System.out.println("Token verified, fresh, and marked as used.");
                }
                return valid;
            }
        }

        csvReader.close();

        if (!found) {
            System.out.println("Token not found!");
        }
        return false;
    }

    
     // Mark a token as used by rewriting the CSV.
     
    public void markTokenAsUsed(String tokenData, String signatureBase64) throws IOException {
        String filePath = "issued_tokens.csv";
        File inputFile = new File(filePath);

        List<String> updatedRows = new ArrayList<>();
        BufferedReader csvReader = new BufferedReader(new FileReader(inputFile));
        String row;

        while ((row = csvReader.readLine()) != null) {
            String[] parts = row.split(",");
            String storedTokenData = parts[0];
            String storedSignature = parts[1];
            String usedFlag = parts[2];

            if (storedTokenData.equals(tokenData) && storedSignature.equals(signatureBase64)) {
                usedFlag = "1";
            }

            updatedRows.add(storedTokenData + "," + storedSignature + "," + usedFlag);
        }
        csvReader.close();

        FileWriter csvWriter = new FileWriter(filePath, false);
        for (String updatedRow : updatedRows) {
            csvWriter.write(updatedRow + "\n");
        }
        csvWriter.flush();
        csvWriter.close();
    }

    // Process a received vote

    public void processVote(String hashedVote, String encryptedVoteBase64, String encryptedBundleBase64) throws Exception {

        // Decrypt {K | tokenData}
        byte[] decryptedBundle = CryptoUtils.decryptRSA(Base64.getDecoder().decode(encryptedBundleBase64), getAuthorityPrivateKey());

        byte[] kBytes = new byte[16];
        System.arraycopy(decryptedBundle, 0, kBytes, 0, 16);
        SecretKey symmetricKey = new SecretKeySpec(kBytes, "AES");

        byte[] tokenBytes = new byte[decryptedBundle.length - 16];
        System.arraycopy(decryptedBundle, 16, tokenBytes, 0, tokenBytes.length);
        String tokenData = new String(tokenBytes);

        // Look up token signature in CSV
        String filePath = "issued_tokens.csv";
        String storedSignature = null;

        BufferedReader csvReader = new BufferedReader(new FileReader(filePath));
        String row;
        while ((row = csvReader.readLine()) != null) {
            String[] parts = row.split(",");
            if (parts[0].equals(tokenData)) {
                storedSignature = parts[1];
                break;
            }
        }
        csvReader.close();

        if (storedSignature == null) {
            System.out.println("Invalid token, not found!");
            return;
        }

        boolean validToken = verifyVoteToken(tokenData, storedSignature);
        if (!validToken) {
            System.out.println("Invalid or expired token!");
            return;
        }

        // Decrypt vote
        byte[] decryptedVoteBytes = CryptoUtils.decryptAES(Base64.getDecoder().decode(encryptedVoteBase64), symmetricKey);
        String vote = new String(decryptedVoteBytes);

        String recomputedHash = CryptoUtils.hashSHA256(vote);
        if (!recomputedHash.equals(hashedVote)) {
            System.out.println("Vote hash mismatch — possible tampering!");
            return;
        }
        saveVoteToCSV(vote);
        System.out.println("Vote accepted for candidate: " + vote);
    }

    public void saveVoteToCSV(String candidate) throws IOException {
        String filePath = "votes.csv";

        // Load existing votes
        Map<String, Integer> tally = new HashMap<>();

        File file = new File(filePath);
        if (file.exists()) {
            BufferedReader csvReader = new BufferedReader(new FileReader(filePath));
            String row;
            while ((row = csvReader.readLine()) != null) {
                String[] parts = row.split(",");
                if (parts.length == 2) {
                    String name = parts[0];
                    int count = Integer.parseInt(parts[1]);
                    tally.put(name, count);
                }
            }
            csvReader.close();
        }

        // Increment count for this candidate
        tally.put(candidate, tally.getOrDefault(candidate, 0) + 1);

        // Overwrite file with updated counts
        FileWriter csvWriter = new FileWriter(filePath, false);
        for (Map.Entry<String, Integer> entry : tally.entrySet()) {
            csvWriter.append(entry.getKey()).append(",").append(String.valueOf(entry.getValue())).append("\n");
        }
        csvWriter.flush();
        csvWriter.close();

        
    }

}
