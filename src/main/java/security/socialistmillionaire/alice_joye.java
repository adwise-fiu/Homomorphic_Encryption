package security.socialistmillionaire;

import security.dgk.DGKOperations;
import security.misc.HomomorphicException;
import security.misc.NTL;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class alice_joye extends alice_veugen {

    public alice_joye() {

    }

    public boolean Protocol1(BigInteger x) throws IOException, ClassNotFoundException, HomomorphicException {
        // Step 1 by Bob
        Object o = fromBob.readObject();
        BigInteger little_y_star;
        int answer;
        int delta_a;
        int delta_b;
        int delta_a_prime;

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

        BigInteger subtract = little_y_star.add(x_prime).subtract(x);
        BigInteger big_z_star = subtract.divide(powT);
        BigInteger little_z_star = subtract.mod(powT);
        toBob.writeObject(little_z_star);
        toBob.flush();

        // Figure 1 compare
        delta_a_prime = Protocol0(x_prime);

        // Step 3 Alice
        if (big_z_star.mod(TWO).equals(BigInteger.ZERO)) {
            delta_a = delta_a_prime;
        }
        else {
            delta_a = delta_a_prime ^ 1;
        }

        // Step 4 Bob

        // Step 5, Extra: get delta_A XOR delta_B
        delta_b = fromBob.readInt();
        answer = delta_a ^ delta_b;

        toBob.writeObject(DGKOperations.encrypt(answer, dgk_public));
        toBob.flush();
        return answer == 1;
    }

    // This function is the equivalent of the protocol on Figure 1 on Joye and Salehi's paper
    private int Protocol0(BigInteger x) throws IOException, ClassNotFoundException, HomomorphicException {
        Object in = fromBob.readObject();
        BigInteger [] Encrypted_Y;
        BigInteger [] C;
        BigInteger [] XOR;
        List<Integer> set_l = new ArrayList<>();
        int t_bits;
        int hamming_weight;
        int delta_a;

        // Step 1: Get Y bits from Bob
        if (in instanceof BigInteger[]) {
            Encrypted_Y = (BigInteger []) in;
        }
        else {
            throw new IllegalArgumentException("Protocol 1 Step 1: Missing Y-bits!");
        }

        // Step 2, Compute Hamming Weight and Select delta A
        hamming_weight = hamming_weight(x);
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

        // Let bob know the correct delta b
        if (x.bitLength() < Encrypted_Y.length) {
            // x <= y is true, so I need delta_a XOR delta_b == 1
            // delta_b = 1 XOR delta_a
            toBob.writeObject(BigInteger.valueOf(1 ^ delta_a));
            toBob.flush();
            //System.out.println("Shouldn't be here: x <= y bits");
            return delta_a;
        }
        else if(x.bitLength() > Encrypted_Y.length) {
            // x <= y is false, so I need delta_a XOR delta_b == 0
            // delta_b = 0 XOR delta_a = delta_a
            toBob.writeObject(BigInteger.valueOf(delta_a));
            toBob.flush();
            //System.out.println("Shouldn't be here: x > y bits");
            return delta_a;
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

        // Want to go from Right to left...
        int set_l_index = 0;
        for (int i = 0; i < Encrypted_Y.length; i++) {

            BigInteger temp;
            BigInteger sum;
            if (delta_a == NTL.bit(x, i)) {
                // right to left
                // 1 + (1 - 2 * delta_a) * x_i
                first_term = 1 + ((1 - 2 * delta_a) * NTL.bit(x, i));
                // (2 * delta_a - 1) * y_i
                second_term = DGKOperations.multiply(Encrypted_Y[i], (2 * delta_a) - 1 , dgk_public);
                // Combine terms..
                temp = DGKOperations.add_plaintext(second_term, first_term, dgk_public);

                // Now add with C_i
                sum = DGKOperations.sum(XOR, dgk_public, i);
                temp = DGKOperations.add(temp, sum, dgk_public);
                // Blind the term and save it
                temp = DGKOperations.multiply(temp, rnd.nextInt(dgk_public.getL()) + 1, dgk_public);
                C[set_l_index] = temp;
                ++set_l_index;
            }
        }
        // Use the same trick as from Veugen, including blinding
        C[set_l.size()] = DGKOperations.sum(XOR, dgk_public);
        C[set_l.size()] = DGKOperations.add_plaintext(C[set_l.size()], delta_a, dgk_public);
        C[set_l.size()] = DGKOperations.multiply(C[set_l.size()], rnd.nextInt(dgk_public.getL()) + 1, dgk_public);

        // Step 4: send shuffled bits to Bob
        C = shuffle_bits(C);
        toBob.writeObject(C);
        toBob.flush();
        return delta_a;
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
