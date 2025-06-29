public class AuthService {

    public boolean authenticate(String username, String nonce, String clientHash) throws Exception {
        if (!VoterDB.isValidUser(username)) {
            return false;
        }

        String storedPassword = VoterDB.getPassword(username);
        String combined = storedPassword + nonce;

        String serverHash = CryptoUtils.hashSHA256(combined);
        
        System.out.println("Server Hash (pw + nonce): " + serverHash);

        return serverHash.equals(clientHash);
    }
    
  
}
