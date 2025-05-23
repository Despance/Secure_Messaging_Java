import java.security.SecureRandom;
import java.util.Base64;

public class Common {

    private static final SecureRandom secureRandom = new SecureRandom(); // thread-safe
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    public static final int PORT_NUMBER = 25565;
    public static final int CA_PORT = 25566;

    public static String generateNonce(int byteLength) {
        byte[] randomBytes = new byte[byteLength];
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }

}
