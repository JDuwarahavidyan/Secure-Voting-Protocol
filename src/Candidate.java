import java.util.Arrays;
import java.util.List;

public class Candidate {

    private static final List<String> candidates = Arrays.asList("A. Alice", "B. Bob", "C. Charlie", "D. David");

    public static List<String> getCandidates() {
        return candidates;
    }

    public static boolean isValidChoice(String choice) {
        // Accept just "A", "B", "C", "D" — not the full string
        List<String> validOptions = Arrays.asList("A", "B", "C", "D");
        return validOptions.contains(choice.toUpperCase());
    }

    public static String getCandidateName(String choice) {
        switch (choice.toUpperCase()) {
            case "A": return "A. Alice";
            case "B": return "B. Bob";
            case "C": return "C. Charlie";
            case "D": return "D. David";
            default: return "Unknown";
        }
    }
}
