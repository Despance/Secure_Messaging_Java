import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

public class Server {

    private ServerSocket server;
    private Socket client;

    private PrintWriter clientOut;
    private BufferedReader clientReader;
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

            this.certificate = getCertificate();

            System.out.println(certificate.toString());

            acceptConnection(server);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private Certificate getCertificate() throws IOException {
        rsa = new RSA();

        System.out.println("My private: " + rsa.getPrivateKey());
        System.out.println("My public: " + rsa.getPublicKey());

        cerfificateAuthority = new Socket(CAIP, Common.CA_PORT);
        CAOut = new PrintWriter(cerfificateAuthority.getOutputStream(), true);
        CAReader = new BufferedReader(new InputStreamReader(cerfificateAuthority.getInputStream()));

        CAOut.println("Get Certificate");
        CAOut.println(RSA.ToEncoded(rsa.getPublicKey()));
        CAOut.flush();

        String ceString = CAReader.readLine();

        Certificate cert = new Certificate(ceString);

        return cert;

    }

    private void acceptConnection(ServerSocket socket) throws IOException {

        client = socket.accept();
        clientOut = new PrintWriter(client.getOutputStream(), true);
        clientReader = new BufferedReader(new InputStreamReader(client.getInputStream()));

        String initialResponse = clientReader.readLine();
        System.out.println("Client says: " + initialResponse);

        byte[] serverNonce = Common.generateNonce();
        clientOut.println(certificate.toString() + " Nonce: " + Base64.getEncoder().encodeToString(serverNonce));
        clientOut.flush();

        cerfificateAuthority = new Socket(CAIP, Common.CA_PORT);
        CAOut = new PrintWriter(cerfificateAuthority.getOutputStream(), true);
        CAReader = new BufferedReader(new InputStreamReader(cerfificateAuthority.getInputStream()));
        CAOut.println("public key ne abi? ben server btw");
        CAOut.flush();

        String CAResponse = CAReader.readLine();
        PublicKey sigKey = RSA.generatePublicKeyFromString(CAResponse);

        System.out.println("CA says my sig is valid: " + certificate.checkSignature(sigKey));
        
        // get RSA encrypted premaster secret from client
        // use private key to decrypt it
        // genenrate master secret and then keys from that
        // listen for messages from client, decrypt using AES and send responses(encypted with aes)
        // do this listten and send in a loop

        cerfificateAuthority.close();

    }
}
