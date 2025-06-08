import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class Client {

    private Socket server;
    private String serverIP;
    private PrintWriter serverOut;
    private BufferedReader serverReader;
    private Certificate serverCertificate;

    private Socket cerfificateAuthority;
    private String CAIP;

    private PrintWriter CAOut;
    private BufferedReader CAReader;
    private Certificate certificate;
    private RSA rsa;

    private Keys keys;
    private AES aes;

    private int keyUpdateCount = 0;
    private MessageHelper messageHelper;
    private KeyGenerationHelper keyGenerationHelper;

    private final String downloadPath = "clientDownloads/";

    public Client(String serverIP, String CAIP) {
        this.CAIP = CAIP;
        this.serverIP = serverIP;
        rsa = new RSA();
        aes = new AES();

        try {
            this.certificate = getCertificate();

            if (this.certificate != null) {
                Logg.getLogger().info("My certificate:" + certificate.toString());

                System.out.println("My Certificate is recieved from CA");
            }

            secureSessionHello();
            // startCommunication();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private Certificate getCertificate() throws IOException {
        cerfificateAuthority = new Socket(CAIP, Common.CA_PORT);
        CAOut = new PrintWriter(cerfificateAuthority.getOutputStream(), true);
        CAReader = new BufferedReader(new InputStreamReader(cerfificateAuthority.getInputStream()));

        CAOut.println("Get Certificate");
        CAOut.println(RSA.ToEncoded(rsa.getPublicKey()));
        CAOut.flush();

        String ceString = CAReader.readLine();
        String caKeyString = CAReader.readLine();

        Certificate cert = new Certificate(ceString);

        PublicKey caPublicKey = RSA.generatePublicKeyFromString(caKeyString);

        return cert.checkSignature(caPublicKey) ? cert : null;

    }

    private void secureSessionHello() throws IOException {

        System.out.println("trying to connect");
        server = new Socket(serverIP, Common.PORT_NUMBER);
        serverOut = new PrintWriter(server.getOutputStream(), true);
        serverReader = new BufferedReader(new InputStreamReader(server.getInputStream()));

        byte[] clientNonce = Common.generateNonce();
        serverOut.println(certificate.toString() + " nonce: " + Base64.getEncoder().encodeToString(clientNonce));
        serverOut.flush();

        String initialResponse = serverReader.readLine();

        Certificate serverCertificateTemp = new Certificate(initialResponse);
        byte[] serverNonce = Common.getNonce(initialResponse);

        cerfificateAuthority = new Socket(CAIP, Common.CA_PORT);
        CAOut = new PrintWriter(cerfificateAuthority.getOutputStream(), true);
        CAReader = new BufferedReader(new InputStreamReader(cerfificateAuthority.getInputStream()));

        CAOut.println("public key ne abi? ben client btw");
        CAOut.flush();

        String CAResponse = CAReader.readLine();
        cerfificateAuthority.close();
        PublicKey caPkey = RSA.generatePublicKeyFromString(CAResponse);

        if (serverCertificateTemp.checkSignature(caPkey)) {
            serverCertificate = serverCertificateTemp;
            System.out.println("Server certificate is valid.");
            Logg.getLogger().info("Client certificate recieved");

        } else
            System.out.println("Server certificate is fraud!!");

        keyGenerationHelper = new KeyGenerationHelper(clientNonce, serverNonce);
        // client generate premaster secret
        byte[] premasterSecret = keyGenerationHelper.generateNewPremasterSecret();
        // encrypt it with server public key RSA and send it to server
        String encryptedPremasterSecret = RSA.encrypt(Base64.getEncoder().encodeToString(premasterSecret),
                serverCertificate.getPublicKey());
        serverOut.println(encryptedPremasterSecret);
        serverOut.flush();
        // generate keys(master secret gen is done in key generation helper)
        keys = keyGenerationHelper.generateNewKeys();
        // init messageHelper for further communication
        messageHelper = new MessageHelper(aes, keys.clientKey, keys.clientMacKey,
                keys.serverKey, keys.serverMacKey, keys.clientIv, keys.serverIv, serverOut, serverReader);
    }

    private void updateKeys() throws IOException {
        System.out.println("Updating keys");
        keys = keyGenerationHelper.updateKeys();
        messageHelper.updateKeys(keys.clientKey, keys.clientMacKey, keys.serverKey, keys.serverMacKey, keys.clientIv,
                keys.serverIv);

    }

    private File handleFileCreation(String fileName, byte[] content) {
        try {
            // Ensure the download directory exists
            File downloadDir = new File(downloadPath);
            if (!downloadDir.exists()) {
                downloadDir.mkdirs();
            }
            File file = new File(downloadPath + fileName);
            Path filePath = Paths.get(file.getAbsolutePath());
            Common.writeFile(filePath, content);
            return file;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private void handleKeyUpdate() {
        try {
            keyUpdateCount++;
            if (keyUpdateCount >= Common.KEY_UPDATE_COUNT) {
                updateKeys();
                keyUpdateCount = 0;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void sendMessage(String content) {
        messageHelper.sendMessage(content, null, MessageType.Text);
        handleKeyUpdate();

    }

    public void sendMessage(String filePath, MessageType type) {
        Path filePathObj = Paths.get(filePath);
        byte[] content;
        try {
            content = Common.readFile(filePathObj);
        } catch (IOException e) {
            System.out.println(App.ANSI_RED + e.getLocalizedMessage() + " not found." + App.ANSI_RESET);
            return;
        }
        String fileName = filePathObj.getFileName().toString();
        String contentBase64 = Base64.getEncoder().encodeToString(content);
        messageHelper.sendMessage(contentBase64, fileName, type);
        handleKeyUpdate();

    }

    public Object receiveMessage() {
        String message = messageHelper.receiveMessage();
        String fileName = messageHelper.getFileName(message);
        // check if it's an ack message
        if (messageHelper.getMessageType(message) == MessageType.Ack) {
            return messageHelper.getMessageContent(message);
        }
        // if not an ack message, handle key update
        handleKeyUpdate();
        // if fileName is null, it means it's an text message without a file
        if (fileName.equals("null") || fileName.isEmpty()) {
            // send ack and return the content
            messageHelper.sendMessage(
                    "ACK for message received at: "
                            + LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm:ss")),
                    null, MessageType.Ack);
            return messageHelper.getMessageContent(message);
        } else {
            // send ack with timestamp and fileName
            messageHelper.sendMessage(
                    "ACK for file " + fileName + " received at: "
                            + LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm:ss")),
                    null,
                    MessageType.Ack);
            return handleFileCreation(fileName, Base64.getDecoder().decode(messageHelper.getMessageContent(message)));
        }

    }

}
