import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.Certificate;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

public class Client {

    private Socket server;
    private String serverIP;
    private PrintWriter serverOut;
    private BufferedReader serverReader;
    private Socket cerfificateAuthority;
    private String CAIP;

    private String certificateString = "This is my certificate";
    private PrintWriter CAOut;
    private BufferedReader CAReader;
    private Curve25519KeyPair keyPair;

    private Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST);

    public static void main(String[] args) {
        System.out.println("Client starts.");

        new Client("localhost", "localhost", null);

    }

    private Client(String serverIP, String CAIP, String certificateString) {
        this.CAIP = CAIP;
        this.serverIP = serverIP;
        this.certificateString = certificateString;

        try {
            if (certificateString == null)
                this.certificateString = getCertificate();

            System.out.println("Certificate: " + this.certificateString);
            connect();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private String getCertificate() throws IOException {
        keyPair = cipher.generateKeyPair();

        cerfificateAuthority = new Socket(CAIP, Common.CA_PORT);
        CAOut = new PrintWriter(cerfificateAuthority.getOutputStream(), true);
        CAReader = new BufferedReader(new InputStreamReader(cerfificateAuthority.getInputStream()));

        CAOut.println("Get Certificate");
        CAOut.println(keyPair.getPublicKey());
        CAOut.flush();

        String ceString = CAReader.readLine();

        return ceString;

    }

    private void connect() throws IOException {

        System.out.println("trying to connect");
        server = new Socket(serverIP, Common.PORT_NUMBER);
        serverOut = new PrintWriter(server.getOutputStream(), true);
        serverReader = new BufferedReader(new InputStreamReader(server.getInputStream()));

        serverOut.println(certificateString + " Nonce: " + Common.generateNonce(16));
        serverOut.flush();

        String initialResponse = serverReader.readLine();
        System.out.println("Server says: " + initialResponse);

        cerfificateAuthority = new Socket(CAIP, Common.CA_PORT);
        CAOut = new PrintWriter(cerfificateAuthority.getOutputStream(), true);
        CAReader = new BufferedReader(new InputStreamReader(cerfificateAuthority.getInputStream()));

        CAOut.println("public key ne abi? ben client btw");
        CAOut.flush();

        String CAResponse = CAReader.readLine();
        System.out.println("CA says: " + CAResponse);

        cerfificateAuthority.close();

    }

}
