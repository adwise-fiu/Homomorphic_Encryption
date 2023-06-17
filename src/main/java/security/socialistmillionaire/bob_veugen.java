package security.socialistmillionaire;

import java.io.IOException;
import java.net.Socket;
import java.security.KeyPair;

public class bob_veugen extends bob {
    public bob_veugen(Socket clientSocket, KeyPair a, KeyPair b, KeyPair c) throws IOException, IllegalArgumentException {
        super(clientSocket, a, b, c);
    }
}
