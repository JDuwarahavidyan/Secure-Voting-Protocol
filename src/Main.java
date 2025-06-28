import java.security.PublicKey;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        AuthService authService = new AuthService();

        System.out.println("=========== Authentication Phase ==========");

        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        String nonce = Nonce.generateNonce();
        System.out.println("Generated nonce: " + nonce);

        String combined = password + nonce;
        String clientHash = CryptoUtils.hashSHA256(combined);
        System.out.println("Client Hash: " + clientHash);

        boolean authenticated = authService.authenticate(username, nonce, clientHash);

        if (authenticated) {
            System.out.println("✅ Authentication successful!");

            // ==== Authority issues token ====
            Authority authority = new Authority();
            Voter voter = new Voter();

            String[] result = authority.issueToken();
            String tokenData = result[0];
            String signatureBase64 = result[1];
            String certificate = result[2];

            System.out.println("\n=========== Authority sends to Voter ===========");
            System.out.println("Token Data: " + tokenData);
            System.out.println("Signature: " + signatureBase64);
            System.out.println("Certificate: " + certificate);

            // ==== Voter verifies ====
            System.out.println("\n=========== Voter verifies token ===========");

            // Use CryptoUtils helper
            PublicKey authorityPubKey = CryptoUtils.decodeRSAPublicKey(certificate);

            boolean valid = voter.verifyToken(tokenData, signatureBase64, authorityPubKey);
            System.out.println("Is Signature Valid? " + valid);

        } else {
            System.out.println("❌ Authentication failed: Invalid user or tampered hash.");
        }

        scanner.close();
    }
}
