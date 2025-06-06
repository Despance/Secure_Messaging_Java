import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Base64;

public class Server {

    private ServerSocket server;
    private Socket client;

    private PrintWriter clientOut;
    private BufferedReader clientReader;
    private Certificate clientCertificate;

    private Socket cerfificateAuthority;
    private String CAIP;

    private Certificate certificate;
    private PrintWriter CAOut;
    private BufferedReader CAReader;
    private RSA rsa;

    private Keys keys;
    private AES aes;

    private int keyUpdateCount = 0;
    private KeyGenerationHelper keyGenerationHelper;
    private MessageHelper messageHelper;

    private final String downloadPath = "serverDownloads/";

    public static void main(String[] args) {

        System.out.println("Server starts.");

        new Server("localhost");

    }

    public Server(String CAIP) {
        this.CAIP = CAIP;

        try {
            server = new ServerSocket(Common.PORT_NUMBER);
            rsa = new RSA();
            aes = new AES();

            this.certificate = getCertificate();

            System.out.println(certificate.toString());

            secureSessionHello(server);
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

    private void secureSessionHello(ServerSocket socket) throws IOException {

        client = socket.accept();
        clientOut = new PrintWriter(client.getOutputStream(), true);
        clientReader = new BufferedReader(new InputStreamReader(client.getInputStream()));

        String initialResponse = clientReader.readLine();

        byte[] serverNonce = Common.generateNonce();
        clientOut.println(certificate.toString() + "nonce: " + Base64.getEncoder().encodeToString(serverNonce));
        clientOut.flush();

        Certificate clientCertificateTemp = new Certificate(initialResponse);
        byte[] clientNonce = Common.getNonce(initialResponse);

        cerfificateAuthority = new Socket(CAIP, Common.CA_PORT);
        CAOut = new PrintWriter(cerfificateAuthority.getOutputStream(), true);
        CAReader = new BufferedReader(new InputStreamReader(cerfificateAuthority.getInputStream()));
        CAOut.println("public key ne abi? ben server btw");
        CAOut.flush();

        String CAResponse = CAReader.readLine();
        cerfificateAuthority.close();
        PublicKey caPkey = RSA.generatePublicKeyFromString(CAResponse);

        if (clientCertificateTemp.checkSignature(caPkey)) {
            clientCertificate = clientCertificateTemp;
            System.out.println("Client certificate is valid.");
        } else
            System.out.println("Client certificate is fraud!!");

        // recieve the premaster secret
        String encryptedPremasterSecret = clientReader.readLine();
        String premasterSecretString = RSA.decrypt(encryptedPremasterSecret, rsa.getPrivateKey());
        byte[] premasterSecret = Base64.getDecoder().decode(premasterSecretString);
        keyGenerationHelper = new KeyGenerationHelper(clientNonce, serverNonce, premasterSecret);
        // generate keys(master secret gen is done in keyGenerationHelper)
        keys = keyGenerationHelper.generateNewKeys();
        // init messageHelper for further communication
        messageHelper = new MessageHelper(aes, keys.serverKey, keys.serverMacKey,
                keys.clientKey, keys.clientMacKey, keys.serverIv, keys.clientIv, clientOut, clientReader);
    }

    private void updateKeys() throws IOException {
        System.out.println("Updating keys");

        keys = keyGenerationHelper.updateKeys();
        messageHelper.updateKeys(keys.serverKey, keys.serverMacKey, keys.clientKey, keys.clientMacKey, keys.serverIv,
                keys.clientIv);
    }

    private void startCommunication() throws IOException {

        // get client message
        messageHelper.receiveMessage();
        // send ack to client
        String ackMessage = "ACK";
        messageHelper.sendMessage(ackMessage, "ack.txt", MessageType.Ack);

        updateKeys();

        messageHelper.receiveMessage();
        // send ack to client
        messageHelper.sendMessage("ACK2", "ack2.txt", MessageType.Ack);

        receiveMessage();
        receiveMessage();
        receiveMessage();
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
            messageHelper.sendMessage("ACK for message received at: " + LocalDateTime.now(), null, MessageType.Ack);
            return messageHelper.getMessageContent(message);
        } else {
            // send ack with timestamp and fileName
            messageHelper.sendMessage("ACK for file " + fileName + " received at: " + LocalDateTime.now(), null,
                    MessageType.Ack);
            return handleFileCreation(fileName, Base64.getDecoder().decode(messageHelper.getMessageContent(message)));
        }
    }
}
