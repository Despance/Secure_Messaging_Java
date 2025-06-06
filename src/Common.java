import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

public class Common {

    private static final SecureRandom secureRandom = new SecureRandom(); // thread-safe

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

    public static byte[] readFile(Path filePath) throws IOException {
        byte[] content = null;
        content = Files.readAllBytes(filePath);

        return content;
    }

    public static void writeFile(Path filePath, byte[] content) throws IOException {
        Files.write(filePath, content);

    }

}
