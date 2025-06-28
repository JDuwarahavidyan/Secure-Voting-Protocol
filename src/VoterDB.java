import java.util.HashMap;
import java.util.Map;

public class VoterDB {

    // In-memory voter DB
    private static final Map<String, String> voterMap = new HashMap<>();

    static {
        voterMap.put("duwarahan", "123");
        voterMap.put("bob", "qwerty456");
        voterMap.put("charlie", "zxcvbn789");
    }

    public static boolean isValidUser(String username) {
        return voterMap.containsKey(username);
    }

    public static String getPassword(String username) {
        return voterMap.get(username);
    }
}
