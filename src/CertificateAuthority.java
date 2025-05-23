import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class CertificateAuthority {
    private ServerSocket server;

    private static String certificatePublicKey = "This is my public key";

    public static void main(String[] args) {
        System.out.println("CA starts.");

        new CertificateAuthority();
    }

    private CertificateAuthority() {
        try {
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
        System.out.println("Client says: " + initialResponse);

        clientOut.println(certificatePublicKey);
        clientOut.flush();
        socket.close();

    }

}
