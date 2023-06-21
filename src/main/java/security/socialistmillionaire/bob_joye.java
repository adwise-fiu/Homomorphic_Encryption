package security.socialistmillionaire;

import security.misc.HomomorphicException;
import security.misc.NTL;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;

public class bob_joye extends bob{
    public bob_joye(KeyPair a, KeyPair b, KeyPair c) throws IllegalArgumentException {
        super(a, b, c);
    }

    public boolean test(BigInteger y) throws IOException, HomomorphicException, ClassNotFoundException {
        // Step 1 by Bob
        int delta_b;
        int delta_b_prime = 0;
        int t = y.bitLength();
        BigInteger powT = TWO.pow(t);
        BigInteger nu = NTL.generateXBitRandom(t);
        BigInteger little_y_star = y.add(nu).add(powT).mod(powT);
        BigInteger big_y_star = y.add(nu).divide(powT);
        toAlice.writeObject(little_y_star);

        // Step 2 by Alice
        Object o = fromAlice.readObject();
        BigInteger little_z_star;
        BigInteger y_prime;
        if (o instanceof BigInteger) {
            little_z_star = (BigInteger) o;
        }
        else {
            throw new HomomorphicException("Invalid Object in Step 2 Bob: " + o.getClass().getName());
        }
        y_prime = little_z_star.subtract(nu).mod(powT);
        BigInteger big_y_prime = little_z_star.subtract(nu).divide(powT);

        // Use Figure 1 comparison
        boolean leq = Protocol1(y_prime);

        // Step 3 Alice

        // Step 4 Bob
        if (big_y_star.add(big_y_prime).mod(TWO).equals(BigInteger.ZERO)) {
            delta_b = delta_b_prime;
        }
        else {
            delta_b = 1 ^ delta_b_prime;
        }

        // Step 5, Extra: get delta_A XOR delta_B
        return true;
    }

    // I can use the same Protocol1 from Veugen's Protocol for basic Protocol
    // For advanced Protocol, I would need to change things, but this is a private comparison too...
}
