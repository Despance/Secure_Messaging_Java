import java.util.InputMismatchException;
import java.util.Scanner;
import java.io.File;
import java.time.LocalTime;

public class App {

    private static Scanner scanner;
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";

    public static void main(String[] args) {

        scanner = new Scanner(System.in);
        System.out.println("Enter mode [(1: Client), (2: Server), (3: Certificate Authority)]:  ");

        int selecton = 0;

        while (selecton == 0) {
            try {
                selecton = scanner.nextInt();
            } catch (InputMismatchException e) {
                System.out.println(e.getMessage());
            }
        }

        switch (selecton) {
            case 1:
                handleClient();
                break;
            case 2:
                handleServer();
                break;
            case 3:
                handleCA();
                break;
            default:
                System.out.println("Invalid selection:" + selecton);
                break;

        }

    }

    private static void handleClient() {
        System.out.println("Client Mode Starting...");

        System.out.println("Enter the server ip: ");
        String serverIP = scanner.next();

        System.out.println("Enter the CA ip: ");
        String caIP = scanner.next();

        if (serverIP.isBlank())
            serverIP = "localhost";
        if (caIP.isBlank())
            caIP = "localhost";

        Client client = new Client(serverIP, caIP);

        Thread inputThread = new Thread(() -> {
            while (true) {
                String input = scanner.nextLine();
                client.sendMessage(input);

            }

        });
        inputThread.start();

        Thread outputThread = new Thread(() -> {
            while (true) {
                Object obj = client.receiveMessage();

                if (obj instanceof String) {
                    if (((String) obj).startsWith("ACK for"))
                        System.out.println(ANSI_GREEN + "[System] " + (String) obj + ANSI_RESET);
                    else
                        System.out
                                .println(ANSI_YELLOW + "[Server " + LocalTime.now() + "] " + (String) obj + ANSI_RESET);
                } else
                    System.out
                            .println(ANSI_YELLOW + "[Server " + LocalTime.now() + "] Recieved file saved at location: "
                                    + ((File) obj).getAbsolutePath() + ANSI_RESET);

            }

        });
        outputThread.start();

    }

    private static void handleServer() {
        System.out.println("Server Mode Starting...");

        System.out.println("Enter the CA IP");
        String caIP = scanner.next();

        if (caIP.isBlank())
            caIP = "localhost";

        Server server = new Server(caIP);

        Thread inputThread = new Thread(() -> {
            while (true) {
                String input = scanner.nextLine();
                server.sendMessage(input);
            }

        });

        Thread outputThread = new Thread(() -> {
            while (true) {
                Object obj = server.receiveMessage();

                if (obj instanceof String) {
                    if (((String) obj).startsWith("ACK for"))
                        System.out.println(ANSI_GREEN + "[System] " + (String) obj + ANSI_RESET);
                    else
                        System.out
                                .println(ANSI_YELLOW + "[Client " + LocalTime.now() + "] " + (String) obj + ANSI_RESET);
                } else
                    System.out
                            .println(ANSI_YELLOW + "[Client " + LocalTime.now() + "] Recieved file saved at location: "
                                    + ((File) obj).getAbsolutePath() + ANSI_RESET);

            }

        });
        outputThread.start();
        inputThread.start();

    }

    private static void handleCA() {
        System.out.println("CA Mode Starting...");
        new CertificateAuthority();
    }

    private static String parseCommand(String str) {

        if (str.startsWith("image:")) {

        } else if (str.startsWith("video:")) {

        } else {
        }

        return null;
    }

}
