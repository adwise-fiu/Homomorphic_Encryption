package security.socialistmillionaire;

import security.dgk.DGKOperations;
import security.misc.HomomorphicException;
import security.misc.NTL;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class alice_joye extends alice {
    public alice_joye(Socket socket) throws IOException {
        super(socket);
    }

    public boolean Protocol1(BigInteger x) throws IOException, ClassNotFoundException, HomomorphicException {
        return Protocol0(x);
    }

    public boolean test(BigInteger x) throws IOException, ClassNotFoundException, HomomorphicException {
        // Step 1 by Bob
        Object o = fromBob.readObject();
        BigInteger little_y_star;
        int delta_a;
        int delta_a_prime = 0;

        if (o instanceof BigInteger) {
            little_y_star = (BigInteger) o;
        }
        else {
            throw new HomomorphicException("Invalid object on Step 1 Alice: " + o.getClass().getName());
        }

        // Step 2 done by Alice
        int t = x.bitLength();
        BigInteger powT = TWO.pow(t);
        BigInteger x_prime = NTL.generateXBitRandom(t);

        BigInteger big_z_star = little_y_star.add(x_prime).subtract(x).divide(powT);
        BigInteger little_z_star =  little_y_star.add(x_prime).subtract(x).mod(powT);
        toAlice.writeObject(little_z_star);

        // Figure 1 compare
        boolean leq = Protocol1(x_prime);

        // Step 3 Alice
        if (big_z_star.mod(TWO).equals(BigInteger.ZERO)) {
            delta_a = delta_a_prime;
        }
        else {
            delta_a = 1 ^ delta_a_prime;
        }

        // Step 4 Bob

        // Step 5, Extra: get delta_A XOR delta_B
        return true;
    }

    // This function is the equivalent of the protocol on Figure 1 on Joye and Salehi's paper
    private boolean Protocol0(BigInteger x) throws IOException, ClassNotFoundException, HomomorphicException {
        Object in = fromBob.readObject();
        BigInteger [] Encrypted_Y;
        BigInteger [] C;
        BigInteger [] XOR;
        List<Integer> set_l = new ArrayList<>();
        int t_bits;
        int hamming_weight;
        int answer;
        int delta_a;
        int delta_b;

        // Step 1: Get Y bits from Bob
        if (in instanceof BigInteger[]) {
            Encrypted_Y = (BigInteger []) in;
        }
        else {
            throw new IllegalArgumentException("Protocol 1 Step 1: Missing Y-bits!");
        }

        if (x.bitLength() < Encrypted_Y.length) {
            toBob.writeObject(BigInteger.ONE);
            toBob.flush();
            return true;
        }
        else if(x.bitLength() > Encrypted_Y.length) {
            toBob.writeObject(BigInteger.ZERO);
            toBob.flush();
            return false;
        }

        // Step 2, Compute Hamming Weight
        hamming_weight = hamming_weight(x);

        // Step 2, Select delta A
        t_bits = x.bitLength();
        double ceiling = Math.ceil(t_bits/2.0);
        double floor = Math.floor(t_bits/2.0);

        if (hamming_weight > floor) {
            delta_a = 0;
        }
        else if (hamming_weight < ceiling) {
            delta_a = 1;
        }
        else {
            delta_a = rnd.nextInt(2);
        }

        // Step 3: Form Set L
        for (int i = 0; i < Encrypted_Y.length; i++) {
            // Break if |L| > floor(t/2)
            if (delta_a == NTL.bit(x, i)) {
                set_l.add(i);
            }
        }
        C = new BigInteger[set_l.size() + 1];

        // if equal bits, proceed!
        // Step 2: compute Encrypted X XOR Y
        XOR = new BigInteger[Encrypted_Y.length];
        for (int i = 0; i < Encrypted_Y.length; i++) {
            if (NTL.bit(x, i) == 1) {
                XOR[i] = DGKOperations.subtract(dgk_public.ONE(), Encrypted_Y[i], dgk_public);
            }
            else {
                XOR[i] = Encrypted_Y[i];
            }
        }

        int first_term;
        BigInteger second_term;
        int index;
        for (int i = 0; i < set_l.size(); i++) {
            index = set_l.get(i);

            C[i] = DGKOperations.sum(XOR, dgk_public, Encrypted_Y.length - 1 - index);
            // 1 + (1 - 2 * delta_a) * x_i
            first_term = 1 + ((1 - 2 * delta_a) * NTL.bit(x, Encrypted_Y.length - 1 - index));
            // (2 * delta_a + 1) * y_i
            second_term = DGKOperations.multiply(Encrypted_Y[Encrypted_Y.length - 1 - index],
                    (2 * delta_a) - 1 , dgk_public);
            // Combine terms...
            C[i] = DGKOperations.add_plaintext(C[i], first_term, dgk_public);
            C[i] = DGKOperations.add(C[i], second_term, dgk_public);
        }
        // Use the same trick as from Veugen
        C[set_l.size()] = DGKOperations.sum(XOR, dgk_public);
        C[set_l.size()] = DGKOperations.add_plaintext(C[set_l.size()], delta_a, dgk_public);

        // Step 4: send shuffled bits to Bob
        C = shuffle_bits(C);
        toBob.writeObject(C);
        toBob.flush();

        // Step 6: Bob looks for any 0's in C_i and computes DeltaB

        // Step 7: Obtain Delta B from Bob
        delta_b = fromBob.readInt();

        // 1 XOR 1 = 0 and 0 XOR 0 = 0, so X > Y
        if (delta_a == delta_b) {
            answer = 0;
        }
        // 1 XOR 0 = 1 and 0 XOR 1 = 1, so X <= Y
        else {
            answer = 1;
        }

        /*
         * Step 8: Bob has the Private key anyway
         * Send him the encrypted answer!
         * Alice and Bob know now without revealing x or y!
         */
        toBob.writeObject(DGKOperations.encrypt(answer, dgk_public));
        toBob.flush();
        return answer == 1;
    }

    private static int hamming_weight(BigInteger value) throws HomomorphicException{
        if (value.signum() < 0) {
            throw new HomomorphicException("I'm unsure if Hamming weight is defined for negative");
        }
        else {
            return value.bitCount();
        }
    }
}
