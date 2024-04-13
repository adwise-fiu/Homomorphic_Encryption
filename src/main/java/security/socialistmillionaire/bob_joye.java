package security.socialistmillionaire;

import security.dgk.DGKOperations;
import security.misc.HomomorphicException;
import security.paillier.PaillierCipher;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class bob_joye extends bob {
    private static final Logger logger = LogManager.getLogger(bob_joye.class);

    public bob_joye(KeyPair a, KeyPair b, KeyPair c) throws IllegalArgumentException {
        super(a, b, c);
    }

    public bob_joye(KeyPair a, KeyPair b) throws IllegalArgumentException {
        super(a, b);
    }

    public boolean Protocol2() throws IOException, ClassNotFoundException, HomomorphicException {
        int t;
        int beta_l_prime;
        BigInteger powT;
        BigInteger little_m_prime;
        BigInteger big_m_prime;
        BigInteger encrypted_delta_l;
        int delta_l;
        int delta_l_prime;
        boolean x_leq_y;

        Object o = readObject();
        if (o instanceof BigInteger) {
            big_m_prime = (BigInteger) o;
        }
        else {
            throw new HomomorphicException("In joye_protocol2(), I did NOT get a BigInteger");
        }

        // Decrypt x to use private comparison
        // We should have the t-bit match what alice is doing
        // We can consider setting both values to be compared as at t-bits exactly.
        // Only plausible if we know the field of possible answers.
        if (isDGK) {
            t = dgk_public.getL();
            big_m_prime = BigInteger.valueOf(DGKOperations.decrypt(big_m_prime, dgk_private));
        }
        else {
            t = dgk_public.getT();
            big_m_prime = PaillierCipher.decrypt(big_m_prime, paillier_private);
        }
        powT = TWO.pow(t);
        little_m_prime = big_m_prime.mod(powT);

        // Create a function to run Protocol1 and capture delta_b?
        // or run a protocol_one, instead of decrypt delta, does same but returns delta_b?
        x_leq_y = Protocol1(little_m_prime);

        o = readObject();
        if (o instanceof BigInteger) {
            encrypted_delta_l = (BigInteger) o;
            delta_l = (int) DGKOperations.decrypt(encrypted_delta_l, dgk_private);
        }
        else {
            throw new HomomorphicException("In joye_protocol2(), I did NOT get a BigInteger");
        }

        if(x_leq_y) {
            delta_l_prime = delta_l ^ 1;
        }
        else {
            delta_l_prime = delta_l;
        }

        // Compare values that did NOT get the mod {2^{t}}
        if (big_m_prime.divide(powT).mod(TWO).equals(BigInteger.ZERO)) {
            beta_l_prime = delta_l_prime;
        }
        else {
            beta_l_prime = 1 ^ delta_l_prime;
        }
        return decrypt_protocol_one(beta_l_prime);
    }
}
