import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;

public class CertificateAuthority {
    private ServerSocket server;
    private RSA rsa;

    public CertificateAuthority() {
        try {
            rsa = new RSA();
            server = new ServerSocket(Common.CA_PORT);

            while (!server.isClosed()) {
                Socket connection = server.accept();
                Logg.getLogger().info("Got a connection request");
                acceptConnection(connection);

            }

        } catch (IOException e) {
            e.printStackTrace();

            Logg.getLogger().warning(e.getLocalizedMessage());
        }

    }

    public void acceptConnection(Socket socket) throws IOException {

        Socket client = socket;

        BufferedReader clientReader = new BufferedReader(new InputStreamReader(client.getInputStream()));
        PrintWriter clientOut = new PrintWriter(client.getOutputStream(), true);

        String initialResponse = clientReader.readLine();

        if (initialResponse.equals("Get Certificate")) {
            Logg.getLogger().info("Got a Certificate Request");
            giveCertificate(clientReader, clientOut);
            Logg.getLogger().info("Certificate sent");
        }
        Logg.getLogger().info("Public key sent");

        clientOut.println(RSA.ToEncoded(rsa.getPublicKey()));

        clientOut.flush();
        socket.close();

    }

    public void giveCertificate(BufferedReader clientReader, PrintWriter clientOut) throws IOException {

        System.out.println("Certificate Request.");

        String secondaryResponse = clientReader.readLine();

        PublicKey pkey = RSA.generatePublicKeyFromString(secondaryResponse);
        Certificate cert = new Certificate(null, pkey, null);

        String signature = RSA.signData(cert.getPublicKey().getEncoded(), rsa.getPrivateKey());

        cert.setSignature(signature);

        clientOut.println(cert.toString());
        clientOut.flush();

        System.out.println("Certificate created: " + cert.toString());
        Logg.getLogger().info("Certificate created: " + cert.toString());

    }

}
