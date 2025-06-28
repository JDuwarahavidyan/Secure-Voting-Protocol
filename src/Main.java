import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        AuthService authService = new AuthService();
    
        // ===== Authentication Phase ======
        System.out.println("=========== Authentication Phase ==========");
        
        // ====== Voter input ======
        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        // ====== Generate nonce ======
        String nonce = Nonce.generateNonce();
        System.out.println("Generated nonce: " + nonce);

        // ====== Compute client-side hash using CryptoUtils ======
        String combined = password + nonce;
        String clientHash = CryptoUtils.hashSHA256(combined);
        System.out.println("Client Hash: " + clientHash);

        // ====== Authenticate ======
        boolean authenticated = authService.authenticate(username, nonce, clientHash);

        if (authenticated) {
            System.out.println("Authentication successful!");
            // TODO: Next step → issue voting token, move to vote phase, etc.
        } else {
            System.out.println("Authentication failed: Invalid user or tampered hash.");
        }

        scanner.close();
    }

}
