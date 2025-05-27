import java.security.SecureRandom;
import java.util.Base64;

public class Common {

    private static final SecureRandom secureRandom = new SecureRandom(); // thread-safe
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    public static final int PORT_NUMBER = 25565;
    public static final int CA_PORT = 25566;

    private static final int NONCE_BYTE_LENGTH = 32;

    public static byte[] generateNonce(int byteLength) {
        byte[] randomBytes = new byte[byteLength];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

    public static byte[] generateNonce(){
        return generateNonce(NONCE_BYTE_LENGTH);
    }

    public static byte[] getNonce(String message){
        return Base64.getDecoder().decode( message.substring(message.indexOf("nonce: ") + 7) );
    }

}
