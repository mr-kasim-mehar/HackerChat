import java.io.*;
import java.net.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ChatClient {
    private static final String SERVER_ADDRESS = "143.244.182.175";
    private static final int PORT = 12345;
    private static SecretKey secretKey;
    private static String username;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in))) {

            System.out.println("[+] Connected to the secure chat server.");
            System.out.print("[+] Enter your username: ");
            username = userInput.readLine();
            out.println(username);

            // Receive and decode secret key from server
            String encodedKey = in.readLine();
            byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
            secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            new Thread(() -> {
                try {
                    String serverMessage;
                    while ((serverMessage = in.readLine()) != null) {
                        String decryptedMsg = decryptMessage(serverMessage);
                        if (!decryptedMsg.equals("[-] ERROR_DECRYPTING")) {
                            System.out.println(decryptedMsg);
                        } else {
                            System.err.println("[-] Error Received an invalid message.");
                        }
                    }
                } catch (IOException e) {
                    System.err.println("[-] Connection lost.");
                }
            }).start();

            System.out.println("\n Available Commands:");
            System.out.println("  /rename <new_name>      ->  Change your username");
            System.out.println("  /list                   ->  Show all online users");
            System.out.println("  /dm <username> <msg>    ->  Send a direct message (DM) to a specific user");
            System.out.println("  Press CTRL + C to exit the chat.\n");

            String userMessage;
            while ((userMessage = userInput.readLine()) != null) {
                out.println(encryptMessage(userMessage));

                if (userMessage.startsWith("/rename ")) {
                    username = userMessage.substring(8).trim();
                    System.out.println("[+] Your name has been changed to: " + username);
                } else if (userMessage.equals("/list")) {
                    System.out.println("[+] Fetching online users...");
                } else if (userMessage.startsWith("/dm ")) {
                    System.out.println("[Success] Direct message sent.");
                }
            }
        } catch (IOException e) {
            System.err.println("[-] Error: Unable to connect to the server.");
        }
    }

    private static String encryptMessage(String message) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
        } catch (Exception e) {
            return "[-] ERROR_ENCRYPTING";
        }
    }

    private static String decryptMessage(String encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedMessage)));
        } catch (Exception e) {
            return "[-] ERROR_DECRYPTING";
        }
    }
}
