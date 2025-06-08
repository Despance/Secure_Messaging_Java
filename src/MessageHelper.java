import java.io.BufferedReader;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MessageHelper {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private AES aes;
    private byte[] aesKeySend;
    private byte[] hmacKeySend;
    private byte[] aesKeyReceive;
    private byte[] hmacKeyReceive;
    private byte[] ivSend;
    private byte[] ivReceive;

    private long sequenceNumberSend = 0;
    private long sequenceNumberReceive = 0;

    private PrintWriter output;
    private BufferedReader input;

    public MessageHelper(AES aes, byte[] aesKeySend, byte[] hmacKeySend, byte[] aesKeyReceive, byte[] hmacKeyReceive,
            byte[] ivSend, byte[] ivReceive, PrintWriter output, BufferedReader input) {
        this.aes = aes;
        this.aesKeySend = aesKeySend;
        this.hmacKeySend = hmacKeySend;
        this.aesKeyReceive = aesKeyReceive;
        this.hmacKeyReceive = hmacKeyReceive;
        this.ivSend = ivSend;
        this.ivReceive = ivReceive;
        this.output = output;
        this.input = input;

        StringBuilder sb = new StringBuilder("AES specs initialized: ");
        sb.append("aesKeySend=").append(Base64.getEncoder().encodeToString(aesKeySend)).append(", ");
        sb.append("hmacKeySend=").append(Base64.getEncoder().encodeToString(hmacKeySend)).append(", ");
        sb.append("aesKeyReceive=").append(Base64.getEncoder().encodeToString(aesKeyReceive)).append(", ");
        sb.append("hmacKeyReceive=").append(Base64.getEncoder().encodeToString(hmacKeyReceive)).append(", ");
        sb.append("ivSend=").append(Base64.getEncoder().encodeToString(ivSend)).append(", ");
        sb.append("ivReceive=").append(Base64.getEncoder().encodeToString(ivReceive)).append(", ");
        sb.append("sequenceNumberSend=").append(sequenceNumberSend).append(", ");
        sb.append("sequenceNumberReceive=").append(sequenceNumberReceive);
        Logg.getLogger().info(sb.toString());
    }

    public void updateKeys(byte[] aesKeySend, byte[] hmacKeySend, byte[] aesKeyReceive, byte[] hmacKeyReceive,
            byte[] ivSend, byte[] ivReceive) {
        this.aesKeySend = aesKeySend;
        this.hmacKeySend = hmacKeySend;
        this.aesKeyReceive = aesKeyReceive;
        this.hmacKeyReceive = hmacKeyReceive;
        this.ivSend = ivSend;
        this.ivReceive = ivReceive;

        StringBuilder sb = new StringBuilder("AES specs updated: ");
        sb.append("aesKeySend=").append(Base64.getEncoder().encodeToString(aesKeySend)).append(", ");
        sb.append("hmacKeySend=").append(Base64.getEncoder().encodeToString(hmacKeySend)).append(", ");
        sb.append("aesKeyReceive=").append(Base64.getEncoder().encodeToString(aesKeyReceive)).append(", ");
        sb.append("hmacKeyReceive=").append(Base64.getEncoder().encodeToString(hmacKeyReceive)).append(", ");
        sb.append("ivSend=").append(Base64.getEncoder().encodeToString(ivSend)).append(", ");
        sb.append("ivReceive=").append(Base64.getEncoder().encodeToString(ivReceive)).append(", ");
        sb.append("sequenceNumberSend=").append(sequenceNumberSend).append(", ");
        sb.append("sequenceNumberReceive=").append(sequenceNumberReceive);
        Logg.getLogger().info(sb.toString());
    }

    public String CreateHMAC(String message, byte[] macKey) {
        try {
            Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
            hmac.init(new SecretKeySpec(macKey, HMAC_ALGORITHM));

            byte[] signatureBytes = hmac.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String createMessageForm(MessageType type, String fileName, String content, byte[] macKey) {
        String hmac = CreateHMAC((type.toString() + fileName + content), macKey);
        content = Base64.getEncoder().encodeToString(content.getBytes());
        String message = "{\"type\": \"" + type.toString() + "\", \"fileName\": \"" + fileName + "\", \"content\": \""
                + content + "\", \"hmac\": \"" + hmac + "\"}";
        return message;
    }

    public MessageType getMessageType(String message) {
        int beginIndex = message.indexOf("type") + 8;
        int endIndex = message.indexOf("\",", beginIndex);
        String typeString = message.substring(beginIndex, endIndex);
        return MessageType.valueOf(typeString);
    }

    public String getMessageContent(String message) {
        int beginIndex = message.indexOf("content") + 11;
        int endIndex = message.indexOf("\",", beginIndex);
        String content = message.substring(beginIndex, endIndex);
        return new String(Base64.getDecoder().decode(content));
    }

    public String getFileName(String message) {
        int beginIndex = message.indexOf("fileName") + 12;
        int endIndex = message.indexOf("\",", beginIndex);
        return message.substring(beginIndex, endIndex);
    }

    public boolean validateMessage(String message, byte[] hmacKey) {
        int beginIndex = message.indexOf("hmac") + 8;
        int endIndex = message.indexOf("\"}", beginIndex);
        String hmac = message.substring(beginIndex, endIndex);

        String type = getMessageType(message).toString();
        String fileName = getFileName(message);
        String content = getMessageContent(message);
        String newHmac = CreateHMAC(type + fileName + content, hmacKey);
        if (hmac.equals(newHmac)) {
            return true;
        }
        return false;
    }

    public void sendMessage(String message, String fileName, MessageType type) {
        String messageWithHmac = createMessageForm(type, fileName, message, hmacKeySend);
        String encryptedMessage = aes.encrypt(messageWithHmac.getBytes(), aesKeySend, ivSend);

        Logg.getLogger().info("sending messageWithHmac: " + messageWithHmac);
        Logg.getLogger().info("sending encryptedMessage: " + encryptedMessage);

        output.println(encryptedMessage);
        output.flush();

        // if sending a new message(non ack)
        if (!type.equals(MessageType.Ack)) {
            // update sender iv and seq num
            sequenceNumberSend++;
            ivSend = xorIV(ivSend, sequenceNumberSend);
        }
    }

    public String receiveMessage() {
        try {
            String encryptedMessage = input.readLine();
            String decryptedMessage = aes.decrypt(encryptedMessage, aesKeyReceive, ivReceive);

            Logg.getLogger().info("recieved encryptedMessage: " + encryptedMessage);
            Logg.getLogger().info("recieved decryptedMessage: " + decryptedMessage);

            if (validateMessage(decryptedMessage, hmacKeyReceive)) {
                MessageType type = getMessageType(decryptedMessage);
                String content = getMessageContent(decryptedMessage);

                if (!type.equals(MessageType.Ack)) {
                    // if received non ack message fron receiver, increment receiver seq num and
                    // receiver iv
                    sequenceNumberReceive++;
                    ivReceive = xorIV(ivReceive, sequenceNumberReceive);
                }
                // LOG ONLY

                Logg.getLogger().info("Received message of type: " + type + " with content: " +
                        content);

            } else {
                System.out.println("Invalid message received.");
                Logg.getLogger().warning("Invalid messaage recieved. - " + decryptedMessage);
            }
            return decryptedMessage;

        } catch (Exception e) {
            e.printStackTrace();
            Logg.getLogger().warning(e.getLocalizedMessage());
        }
        return null;
    }

    private byte[] xorIV(byte[] iv, long sequenceNumber) {
        byte[] seqNum = ByteBuffer.allocate(16).putLong(8, sequenceNumber).array();
        byte[] result = new byte[16];
        for (int i = 0; i < iv.length; i++) {
            result[i] = (byte) (iv[i] ^ seqNum[i]);
        }
        return result;
    }

}
