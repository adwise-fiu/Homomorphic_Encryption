package security.socialistmillionaire;

import security.dgk.DGKOperations;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;

public class bob_joye extends bob_veugen {
    public bob_joye(KeyPair a, KeyPair b, KeyPair c) throws IllegalArgumentException {
        super(a, b, c);
    }

    public bob_joye(KeyPair a, KeyPair b) throws IllegalArgumentException {
        super(a, b);
    }

}
