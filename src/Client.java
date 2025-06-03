import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;
import java.security.PublicKey;
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
    
    // TODO: gotta find a better way to hold this(master secret and nonces)...
    // maybe keygenhelper as a object and holding it there?
    private byte[] masterSecret;
    private byte[] clientNonce;
    private byte[] serverNonce;

    public static void main(String[] args) {
        System.out.println("Client starts.");

        new Client("localhost", "localhost");

    }

    private Client(String serverIP, String CAIP) {
        this.CAIP = CAIP;
        this.serverIP = serverIP;
        rsa = new RSA();
        aes = new AES();

        System.out.println("My private: " + rsa.getPrivateKey());
        System.out.println("My public: " + rsa.getPublicKey());

        try {
            this.certificate = getCertificate();

            secureSessionHello();
            startCommunication();
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

        clientNonce = Common.generateNonce();
        serverOut.println(certificate.toString() + " nonce: " + Base64.getEncoder().encodeToString(clientNonce));
        serverOut.flush();

        String initialResponse = serverReader.readLine();
        System.out.println("Server says: " + initialResponse);

        Certificate serverCertificateTemp = new Certificate(initialResponse);
        serverNonce = Common.getNonce(initialResponse);

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
        } else
            System.out.println("Server certificate is fraud!!");

        generateKeys(clientNonce, serverNonce);

    }

    private void generateKeys(byte[] clientNonce, byte[] serverNonce) throws IOException{
        // client generate premaster secret
        byte[] premasterSecret = KeyGenerationHelper.generatePremasterSecret();
        // encrypt it with server public key RSA and send it to server
        String encryptedPremasterSecret = RSA.encrypt(Base64.getEncoder().encodeToString(premasterSecret), serverCertificate.getPublicKey());
        serverOut.println(encryptedPremasterSecret);
        serverOut.flush();
        // generate master secret with premaster secret
        masterSecret = KeyGenerationHelper.generateMasterSecret(premasterSecret, clientNonce, serverNonce);
        // generate keys using master secret
        keys = KeyGenerationHelper.generateKeys(masterSecret, clientNonce, serverNonce);
    }

    private void updateKeys(MessageHelper messageHelper) throws IOException{
        masterSecret = KeyGenerationHelper.updateMasterSecret(masterSecret, clientNonce, serverNonce);
        keys = KeyGenerationHelper.generateKeys(masterSecret, clientNonce, serverNonce);
        messageHelper.updateKeys(keys.clientKey, keys.clientMacKey, keys.serverKey, keys.serverMacKey, keys.clientIv, keys.serverIv);

    }

    private void startCommunication() throws IOException{
        MessageHelper messageHelper = new MessageHelper(aes, keys.clientKey, keys.clientMacKey, 
        keys.serverKey, keys.serverMacKey, keys.clientIv, keys.serverIv, serverOut, serverReader);
        // send message encrypted with AES to server
        String tmpStr = "moin ik bims der client";
        // send message
        messageHelper.sendMessage(tmpStr, "hi.txt" ,MessageType.Text);
        // receive ack from server
        messageHelper.receiveMessage();

        // update keys
        updateKeys(messageHelper);

        messageHelper.sendMessage("moin ik bims der client 2", "hi2.txt", MessageType.Text);
        // receive ack from server
        messageHelper.receiveMessage();

    }


    
}
