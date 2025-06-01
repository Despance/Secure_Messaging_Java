import java.io.BufferedReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MessageHelper {
    
    private static final String HMAC_ALGORITHM = "HmacSHA256";



    public static String CreateHMAC(String message, byte[] macKey){
        try{
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            hmac.init( new SecretKeySpec(macKey, HMAC_ALGORITHM) );

            byte[] signatureBytes = hmac.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(signatureBytes);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static String createMessageForm(MessageType type, String content, byte[] macKey){
        String hmac = CreateHMAC( (type.toString()+content), macKey);
        String message = "{\"type\": \"" + type.toString() + "\", \"content\": \"" + content + "\", \"hmac\": \"" + hmac + "\"}";
        return message;
    }

    public static MessageType getMessageType(String message){
        int beginIndex = message.indexOf("type") + 8;
        int endIndex = message.indexOf("\",", beginIndex);
        String typeString = message.substring(beginIndex, endIndex);
        return MessageType.valueOf(typeString);
    }

    public static String getMessageContent(String message){
        int beginIndex = message.indexOf("content") + 11;
        int endIndex = message.indexOf("\",", beginIndex);
        return message.substring(beginIndex, endIndex);
    }

    public static boolean validateMessage(String message, byte[] hmacKey){
        int beginIndex = message.indexOf("hmac") + 8;
        int endIndex = message.indexOf("\"}", beginIndex);
        String hmac = message.substring(beginIndex, endIndex);

        String type = getMessageType(message).toString();
        String content = getMessageContent(message);
        String newHmac = CreateHMAC(type + content, hmacKey);
        if(hmac.equals(newHmac)){
            return true;
        }
        return false;
    }

    public static void sendMessage(String message, MessageType type, AES aes, byte[] aesKey, byte[] hmacKey, PrintWriter output){
        String messageWithHmac = MessageHelper.createMessageForm(type , message, hmacKey);
        String encryptedMessage = aes.encrypt(messageWithHmac.getBytes(), aesKey);
        output.println(encryptedMessage);
        output.flush();
    }

    public static String receiveMessage(AES aes, byte[] aesKey, byte[] hmacKey, BufferedReader serverReader){
        try {
            String encryptedMessage = serverReader.readLine();
            String decryptedMessage = aes.decrypt(encryptedMessage, aesKey);
            
            if(MessageHelper.validateMessage(decryptedMessage, hmacKey)){
                MessageType type = MessageHelper.getMessageType(decryptedMessage);
                String content = MessageHelper.getMessageContent(decryptedMessage);
                System.out.println("Received message of type: " + type + " with content: " + content);
            }else{
                System.out.println("Invalid message received.");
            }
            return decryptedMessage;

        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


}
