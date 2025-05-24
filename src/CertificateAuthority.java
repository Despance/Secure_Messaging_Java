import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

public class CertificateAuthority {
    private ServerSocket server;

    private static Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST);
    private static Curve25519KeyPair keyPair;

    public static void main(String[] args) {
        System.out.println("CA starts.");

        new CertificateAuthority();
    }

    private CertificateAuthority() {
        try {
            keyPair = cipher.generateKeyPair();
            server = new ServerSocket(Common.CA_PORT);

            while (!server.isClosed()) {
                Socket connection = server.accept();

                acceptConnection(connection);

            }

        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void acceptConnection(Socket socket) throws IOException {

        Socket client = socket;

        BufferedReader clientReader = new BufferedReader(new InputStreamReader(client.getInputStream()));
        PrintWriter clientOut = new PrintWriter(client.getOutputStream(), true);

        String initialResponse = clientReader.readLine();

        if (initialResponse.equals("Get Certificate"))
            giveCertificate(clientReader, clientOut);
        else
            clientOut.println(keyPair.getPublicKey());

        clientOut.flush();
        socket.close();

    }

    public void giveCertificate(BufferedReader clientReader, PrintWriter clientOut) throws IOException {

        System.out.println("Certificate Request.");

        String secondaryResponse = clientReader.readLine();

        System.out.println("got public key " + secondaryResponse);
        String certificate = cipher.calculateSignature(keyPair.getPrivateKey(), secondaryResponse.getBytes())
                .toString();

        clientOut.println(certificate);
        clientOut.flush();
        System.out.println("Certificate created: " + certificate);

    }

}
