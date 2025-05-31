import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Common {

    private static final SecureRandom secureRandom = new SecureRandom(); // thread-safe
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    public static final int PORT_NUMBER = 25565;
    public static final int CA_PORT = 25566;

    private static final int NONCE_BYTE_LENGTH = 32;
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    
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

    public static String CreateHMAC(String message, byte[] macKey){
        try{
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            hmac.init( new SecretKeySpec(macKey, HMAC_ALGORITHM) );

            byte[] signatureBytes = hmac.doFinal(message.getBytes());
            return base64Encoder.encodeToString(signatureBytes);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static String createMessageForm(MessageType type, String content, byte[] macKey) {
        String hmac = CreateHMAC( (type.toString()+content), macKey);
        String message = "{\"type\": \"" + type.toString() + "\", \"content\": \"" + content + "\", \"hmac\": \"" + hmac + "\"}";
        return message;
    }

}
