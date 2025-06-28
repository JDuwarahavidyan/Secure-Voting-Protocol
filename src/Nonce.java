import java.security.SecureRandom;
import java.util.Base64;

public class Nonce {
	  public static String generateNonce() {
	        SecureRandom secureRandom = new SecureRandom();
	        byte[] nonceBytes = new byte[16]; // 128-bit nonce
	        secureRandom.nextBytes(nonceBytes);
	        return Base64.getEncoder().encodeToString(nonceBytes);
	    }

	 
}
