import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;


public class AES {
    
    public static Cipher cipher;

// premaster secreti secure random ile 48 byte bi string generate etcez. 
    public AES(){
        try {
            cipher = Cipher.getInstance("AES");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encrypt(byte[] message, SecretKey secretKey) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(message);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(String encryptedMessage, SecretKey secretKey) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
