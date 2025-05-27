import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;

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

        clientOut.println(certificate.toString());
        clientOut.flush();

        Certificate clientCertificateTemp = new Certificate(initialResponse);

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

        cerfificateAuthority.close();

    }
}
