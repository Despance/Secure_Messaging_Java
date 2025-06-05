import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

public class Common {

    private static final SecureRandom secureRandom = new SecureRandom(); // thread-safe
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    public static final int PORT_NUMBER = 25561;
    public static final int CA_PORT = 25566;

    private static final int NONCE_BYTE_LENGTH = 32;

    public static final int KEY_UPDATE_COUNT = 10; // Number of key updates before a new key is generated

    public static byte[] generateNonce(int byteLength) {
        byte[] randomBytes = new byte[byteLength];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

    public static byte[] generateNonce() {
        return generateNonce(NONCE_BYTE_LENGTH);
    }

    public static byte[] getNonce(String message) {
        return Base64.getDecoder().decode(message.substring(message.indexOf("nonce: ") + 7));
    }

    public static String readFile(Path filePath){
        String content = "";
        try{
            content = new String(Files.readAllBytes(filePath));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return content;
    }

    public static void writeFile(Path filePath, String content) {
        try {
            Files.write(filePath, content.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
