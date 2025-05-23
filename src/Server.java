import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    private ServerSocket server;
    private Socket client;

    private PrintWriter clientOut;
    private BufferedReader clientReader;
    private Socket cerfificateAuthority;
    private String CAIP;

    private String certificateString = "This is my certificate";
    private PrintWriter CAOut;
    private BufferedReader CAReader;

    public static void main(String[] args) {

        System.out.println("Server starts.");

        new Server("localhost", "This is my certificate from server");

    }

    private Server(String CAIP, String certificateString) {
        this.CAIP = CAIP;
        this.certificateString = certificateString;

        try {
            server = new ServerSocket(Common.PORT_NUMBER);

            acceptConnection(server);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private void acceptConnection(ServerSocket socket) throws IOException {

        client = socket.accept();
        clientOut = new PrintWriter(client.getOutputStream(), true);
        clientReader = new BufferedReader(new InputStreamReader(client.getInputStream()));

        String initialResponse = clientReader.readLine();
        System.out.println("Client says: " + initialResponse);

        clientOut.println(certificateString + " Nonce: " + Common.generateNonce(16));
        clientOut.flush();

        cerfificateAuthority = new Socket(CAIP, Common.CA_PORT);
        CAOut = new PrintWriter(cerfificateAuthority.getOutputStream(), true);
        CAReader = new BufferedReader(new InputStreamReader(cerfificateAuthority.getInputStream()));
        CAOut.println("public key ne abi? ben server btw");
        CAOut.flush();

        String CAResponse = CAReader.readLine();
        System.out.println("CA says: " + CAResponse);

        cerfificateAuthority.close();

    }
}
