package security.socialistmillionaire;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;

public class bob_joye extends bob{
    public bob_joye(KeyPair a, KeyPair b, KeyPair c) throws IllegalArgumentException {
        super(a, b, c);
    }

    // I can use the same Protocol1 from Veugen's Protocol for basic Protocol
    // For advanced Protocol, I would need to change things, but this is a private comparison too...
}
