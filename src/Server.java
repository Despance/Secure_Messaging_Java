import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;

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

        clientOut.println(certificate.toString() + " Nonce: " + Common.generateNonce(16));
        clientOut.flush();

        cerfificateAuthority = new Socket(CAIP, Common.CA_PORT);
        CAOut = new PrintWriter(cerfificateAuthority.getOutputStream(), true);
        CAReader = new BufferedReader(new InputStreamReader(cerfificateAuthority.getInputStream()));
        CAOut.println("public key ne abi? ben server btw");
        CAOut.flush();

        String CAResponse = CAReader.readLine();
        PublicKey sigKey = RSA.generatePublicKeyFromString(CAResponse);

        System.out.println("CA says my sig is valid: " + certificate.checkSignature(sigKey));

        cerfificateAuthority.close();

    }
}
