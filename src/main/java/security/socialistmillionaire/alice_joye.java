package security.socialistmillionaire;

import security.dgk.DGKOperations;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class alice_joye extends alice_veugen {

    public alice_joye() {
        super();
    }
/*
    public boolean Protocol1(BigInteger x) throws IOException, ClassNotFoundException, HomomorphicException {
        // Step 1 by Bob
        Object o = readObject();
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
        delta_a_prime = get_delta_a_prime(x_prime);

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
*/
    public boolean Protocol2(BigInteger x, BigInteger y) throws IOException, HomomorphicException, ClassNotFoundException {
        int deltaB;
        int x_leq_y;
        int deltaA = rnd.nextInt(2);
        Object bob;
        BigInteger alpha_lt_beta;
        BigInteger z;
        BigInteger zeta_one;
        BigInteger zeta_two;
        BigInteger result;
        BigInteger r;
        BigInteger alpha;

        /*
         * Step 1: 0 <= r < N
         * N is the Paillier plain text space, which is 1024-bits usually
         * u is the DGK plain text space, which is l bits
         *
         * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
         * Send Z to Bob
         * [[x + 2^l + r]]
         * [[z]] = [[x - y + 2^l + r]]
         */
        if (isDGK) {
            r = NTL.RandomBnd(dgk_public.getU());
            z = DGKOperations.add_plaintext(x, r.add(powL).mod(dgk_public.getU()), dgk_public);
            z = DGKOperations.subtract(z, y, dgk_public);
        }
        else {
            r = NTL.RandomBnd(paillier_public.getN());
            z = PaillierCipher.add_plaintext(x, r.add(powL).mod(paillier_public.getN()), paillier_public);
            z = PaillierCipher.subtract(z, y, paillier_public);
        }
        toBob.writeObject(z);
        toBob.flush();

        // Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

        // Step 3: alpha = r (mod 2^l)
        alpha = NTL.POSMOD(r, powL);

        // Step 4: Modified Protocol 3 or Protocol 3

        // See Optimization 3: true --> Use Modified Protocol 3
        if(Protocol1(alpha)) {
            x_leq_y = 1;
        }
        else {
            x_leq_y = 0;
        }

        // Step 5: get Delta B and [[z_1]] and [[z_2]]
        if(deltaA == x_leq_y) {
            deltaB = 0;
        }
        else {
            deltaB = 1;
        }

        bob = readObject();
        if (bob instanceof BigInteger) {
            zeta_one = (BigInteger) bob;
        }
        else {
            throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_1 not found, Invalid object: " +  bob.getClass().getName());
        }

        bob = readObject();
        if (bob instanceof BigInteger) {
            zeta_two = (BigInteger) bob;
        }
        else {
            throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_2 not found, Invalid object: " + bob.getClass().getName());
        }

        // Step 6: Compute [[beta <= alpha]]
        if(isDGK) {
            if(deltaA == 1) {
                alpha_lt_beta = DGKOperations.encrypt(deltaB, dgk_public);
            }
            else {
                alpha_lt_beta = DGKOperations.encrypt(1 - deltaB, dgk_public);
            }

            // Step 7: Compute [[x > y]]
            if(r.compareTo(dgk_public.getU().subtract(BigInteger.ONE).divide(TWO)) < 0) {
                result = DGKOperations.
                        subtract(zeta_one, DGKOperations.encrypt(r.divide(powL), dgk_public), dgk_public);
            }
            else {
                result = DGKOperations.subtract(zeta_two, DGKOperations.encrypt(r.divide(powL), dgk_public), dgk_public);
            }
            result = DGKOperations.subtract(result, alpha_lt_beta, dgk_public);
        }
        else
        {
            if(deltaA == 1) {
                alpha_lt_beta = PaillierCipher.encrypt(deltaB, paillier_public);
            }
            else {
                alpha_lt_beta = PaillierCipher.encrypt(1 - deltaB, paillier_public);
            }

            // Step 7: Compute [[x >= y]]
            if(r.compareTo(paillier_public.getN().subtract(BigInteger.ONE).divide(TWO)) < 0) {
                result = PaillierCipher.subtract(zeta_one, PaillierCipher.encrypt(r.divide(powL), paillier_public), paillier_public);
            }
            else {
                result = PaillierCipher.subtract(zeta_two, PaillierCipher.encrypt(r.divide(powL), paillier_public), paillier_public);
            }
            result = PaillierCipher.subtract(result, alpha_lt_beta, paillier_public);
        }

        /*
         * Unofficial Step 8:
         * Since the result is encrypted...I need to send
         * this back to Bob (Android Phone) to decrypt the solution...
         *
         * Bob by definition would know the answer as well.
         */
        return decrypt_protocol_two(result);
    }

    public boolean Protocol1(BigInteger x) throws IOException, ClassNotFoundException, HomomorphicException {
        int delta_a_prime = compute_delta_a(x);
        int delta_b_prime;
        int xor;
        boolean answer = Protocol0(x, delta_a_prime);
        if (answer) {
            delta_b_prime = 1 ^ delta_a_prime;
        }
        else {
            delta_b_prime = delta_a_prime;
        }
        xor = delta_a_prime ^ delta_b_prime;
        assert answer == (xor == 1);
        return answer;
    }

     /*
    private int get_delta_a_prime(BigInteger x) throws IOException, ClassNotFoundException, HomomorphicException {
        int delta_a_prime = compute_delta_a(x);
        int delta_b_prime;
        int xor;
        boolean answer = Protocol0(x, delta_a_prime);
        if (answer) {
            delta_b_prime = 1 ^ delta_a_prime;
        }
        else {
            delta_b_prime = delta_a_prime;
        }
        xor = delta_a_prime ^ delta_b_prime;
        // Confirm the delta is correct before continuing
        assert answer == (xor == 1);
        return delta_a_prime;
    }
     */

    // This function is the equivalent of the protocol on Figure 1 on Joye and Salehi's paper
    private boolean Protocol0(BigInteger x, int delta_a) throws IOException, ClassNotFoundException, HomomorphicException {
        int delta_b;
        BigInteger [] Encrypted_Y;
        BigInteger [] C;
        BigInteger [] XOR;
        List<Integer> set_l = new ArrayList<>();

        // Step 1: Get Y bits from Bob
        Object in = readObject();
        if (in instanceof BigInteger[]) {
            Encrypted_Y = (BigInteger []) in;
        }
        else {
            throw new IllegalArgumentException("Protocol 1 Step 1: Missing Y-bits!");
        }

        BigInteger early_terminate = unequal_bit_check(x, Encrypted_Y);
        if (early_terminate.equals(BigInteger.ONE)) {
            return true;
        }
        else if (early_terminate.equals(BigInteger.ZERO)) {
            return false;
        }

        int floor_t_div_two = (int) Math.floor((float) Encrypted_Y.length/2);

        // Step 3: Form Set L
        for (int i = 0; i < Encrypted_Y.length; i++) {
            // Break if |L| > floor(t/2)
            if (delta_a == NTL.bit(x, i)) {
                set_l.add(i);
            }
        }

        // I need to confirm that #L = floor(t/2) always
        // This is how I protect against timing attacks.
        for (int i = 0; i < Encrypted_Y.length; i++) {
            if (set_l.size() == floor_t_div_two) {
                break;
            }
            if (!set_l.contains(i)) {
                set_l.add(i);
            }
        }
        // Confirm the value #L = floor(t/2), no more, no less.
        assert floor_t_div_two == set_l.size();
        C = new BigInteger[set_l.size() + 1];

        // if equal bits, proceed!
        // Step 2: compute Encrypted X XOR Y
        XOR = encrypted_xor(x, Encrypted_Y);

        int first_term;
        BigInteger second_term;

        // Want to go from Right to left...
        int set_l_index = 0;
        for (int i = 0; i < Encrypted_Y.length; i++) {
            BigInteger temp;
            BigInteger sum;
            if (set_l.contains(i)) {
                // right to left
                // 1 + (1 - 2 * delta_a) * x_i
                first_term = 1 + ((1 - 2 * delta_a) * NTL.bit(x, i));
                // (2 * delta_a - 1) * y_i
                second_term = DGKOperations.multiply(Encrypted_Y[i], (2L * delta_a) - 1, dgk_public);
                // Combine terms.
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
        writeObject(C);
   
        // Get Delta B from Bob
        delta_b = fromBob.readInt();
        int answer = delta_a ^ delta_b;
        return answer == 1;
    }

    private static int compute_delta_a(BigInteger x) throws HomomorphicException {
        // Step 2, Compute Hamming Weight and Select delta A
        int delta_a;
        int hamming_weight = hamming_weight(x);
        int t_bits = x.bitLength();
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
        return delta_a;
    }

    private static int hamming_weight(BigInteger value) throws HomomorphicException {
        if (value.signum() < 0) {
            throw new HomomorphicException("I'm unsure if Hamming weight is defined for negative");
        }
        else {
            return value.bitCount();
        }
    }
}
