import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSA {

    private static final String ALGORITHM = "RSA";
    public static Cipher cipher;
    private PublicKey publicKey;

    private PrivateKey privateKey;

    public RSA() {

        try {
            cipher = Cipher.getInstance(ALGORITHM);

            if (publicKey == null || privateKey == null) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
                generator.initialize(2048);

                KeyPair keyPair = generator.generateKeyPair();

                publicKey = keyPair.getPublic();
                privateKey = keyPair.getPrivate();

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static String encrypt(String message, Key publicKey) {

        try {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedBytes = cipher.doFinal(message.getBytes());

            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;

    }

    public static String signData(byte[] data, PrivateKey key) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update(data);

            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String cipherText, Key privateKey) {

        try {
            byte[] decoded = Base64.getDecoder().decode(cipherText);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decryptedBytes = cipher.doFinal(decoded);

            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static PublicKey generatePublicKeyFromString(String publicKeyString) {
        KeyFactory keyFactory;
        try {

            keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));

            return keyFactory.generatePublic(publicKeySpec);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public static String ToEncoded(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

}
