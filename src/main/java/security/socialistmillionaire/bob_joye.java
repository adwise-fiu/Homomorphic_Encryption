package security.socialistmillionaire;

import java.io.IOException;
import java.net.Socket;
import java.security.KeyPair;

public class bob_joye extends bob{
    public bob_joye(Socket clientSocket, KeyPair a, KeyPair b, KeyPair c) throws IOException, IllegalArgumentException {
        super(clientSocket, a, b, c);
    }
}
