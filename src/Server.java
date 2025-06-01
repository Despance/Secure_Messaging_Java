import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

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

    public static void main(String[] args) {

        System.out.println("Server starts.");

        new Server("localhost");

    }

    private Server(String CAIP) {
        this.CAIP = CAIP;

        try {
            server = new ServerSocket(Common.PORT_NUMBER);
            rsa = new RSA();

            this.certificate = getCertificate();

            System.out.println(certificate.toString());

            secureSessionHello(server);
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
        // generate master secret
        byte[] masterSecret = KeyGenerationHelper.generateMasterSecret(premasterSecret, clientNonce, serverNonce);
        // generate keys
        Keys keys = KeyGenerationHelper.generateKeys(masterSecret, clientNonce, serverNonce);
        AES aes = new AES();
        
        // get client message
        MessageHelper.receiveMessage(aes, keys.clientKey, keys.clientMacKey, clientReader);
        // send ack to client
        String ackMessage = "ACK";
        MessageHelper.sendMessage(ackMessage, MessageType.Ack, aes, keys.serverKey, keys.serverMacKey, clientOut);


        cerfificateAuthority.close();

    }
}
