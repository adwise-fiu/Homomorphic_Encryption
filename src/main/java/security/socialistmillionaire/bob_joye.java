package security.socialistmillionaire;

import security.dgk.DGKOperations;
import security.misc.HomomorphicException;
import security.misc.NTL;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;

public class bob_joye extends bob_veugen {
    public bob_joye(KeyPair a, KeyPair b, KeyPair c) throws IllegalArgumentException {
        super(a, b, c);
    }

    /*
    public boolean Protocol1(BigInteger y) throws IOException, HomomorphicException, ClassNotFoundException {
        // Step 1 by Bob
        int delta_b;
        int delta_b_prime;
        int t = y.bitLength();
        BigInteger powT = TWO.pow(t);
        BigInteger nu = NTL.generateXBitRandom(t);
        BigInteger little_y_star = y.add(nu).mod(powT);
        BigInteger big_y_star = y.add(nu).divide(powT);
        toAlice.writeObject(little_y_star);
        toAlice.flush();

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
        delta_b_prime = Protocol0(y_prime);

        // Step 3 Alice

        // Step 4 Bob
        if (big_y_star.add(big_y_prime).mod(TWO).equals(BigInteger.ZERO)) {
            delta_b = delta_b_prime;
        }
        else {
            delta_b = delta_b_prime ^ 1;
        }
        // Step 5, Extra: get delta_A XOR delta_B
        toAlice.writeInt(delta_b);
        toAlice.flush();

        o = fromAlice.readObject();
        if (o instanceof BigInteger) {
            return DGKOperations.decrypt((BigInteger) o, dgk_private) == 1;
        }
        else {
            throw new HomomorphicException("Invalid Object: " + o.getClass().getName());
        }
    }
     */
    public boolean Protocol1(BigInteger y)
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {

        int [] bits = new int[2];
        boolean answer = Protocol0(y, bits);
        int xor = bits[0] ^ bits[1];
        //assert answer == (xor == 1);
        return answer;
    }

    // Based on Figure 1 from Joye paper
    // This had modifications, so I can test leq and recover delta b
    private boolean Protocol0(BigInteger y, int [] bits)
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {
        // Constraint...
        if(y.bitLength() > dgk_public.getL()) {
            throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, y is: " + y.bitLength() + " bits");
        }

        boolean answer;
        Object in;
        int delta_b = 0;
        int delta_a;
        BigInteger [] C;
        BigInteger temp;

        //Step 1: Bob sends encrypted bits to Alice
        BigInteger [] EncY = new BigInteger[y.bitLength()];
        for (int i = 0; i < y.bitLength(); i++) {
            EncY[i] = DGKOperations.encrypt(NTL.bit(y, i), dgk_public);
        }
        toAlice.writeObject(EncY);
        toAlice.flush();

        // Step 2: Alice computes delta_a and just sends now...
        delta_a = fromAlice.readInt();

        // Step 3: Alice...
        // Step 4: Alice...
        // Step 5: Alice...

        // Step 6: Check if one of the numbers in C_i is decrypted to 0.
        in = fromAlice.readObject();
        if(in instanceof BigInteger[]) {
            C = (BigInteger []) in;
        }
        else if (in instanceof BigInteger) {
            temp = (BigInteger) in;
            if (temp.equals(BigInteger.ONE)) {
                // x <= y is true, so I need delta_a XOR delta_b == 1
                // Alice will give you the delta_a for you to compute delta_b
                // delta_b = 1 XOR delta_a
                delta_b = 1 ^ delta_a;
                bits[0] = delta_a;
                bits[1] = delta_b;
                return true;
            }
            else if (temp.equals(BigInteger.ZERO)) {
                // x <= y is false, so I need delta_a XOR delta_b == 0
                // delta_b = 0 XOR delta_a = delta_a
                delta_b = delta_a;
                bits[0] = delta_a;
                bits[1] = delta_b;
                return false;
            }
            else {
                throw new IllegalArgumentException("This shouldn't be possible, value is: " + temp);
            }
        }
        else {
            throw new IllegalArgumentException("Protocol 1, Step 6: Invalid object: " + in.getClass().getName());
        }

        for (BigInteger C_i: C) {
            if (DGKOperations.decrypt(C_i, dgk_private) == 0) {
                delta_b = 1;
                break;
            }
        }

        toAlice.writeInt(delta_b);
        toAlice.flush();

        answer = (delta_a ^ delta_b) == 1;
        bits[0] = delta_a;
        bits[1] = delta_b;
        return answer;
    }
}
