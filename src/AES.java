import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {

    private Cipher cipher;

    // AES with CTR mode and key size of 256 bits and iv of 128 bits
    public AES() {
        try {
            cipher = Cipher.getInstance("AES/CTR/NoPadding");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encrypt(byte[] message, byte[] secretKeyByte, byte[] iv) {
        try {
            SecretKey secretKey = new SecretKeySpec(secretKeyByte, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encryptedBytes = cipher.doFinal(message);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(String encryptedMessage, byte[] secretKeyByte, byte[] iv) {
        try {
            SecretKey secretKey = new SecretKeySpec(secretKeyByte, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
