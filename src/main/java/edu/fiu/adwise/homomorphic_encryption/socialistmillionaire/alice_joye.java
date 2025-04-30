/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.socialistmillionaire;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKOperations;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierCipher;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class alice_joye extends alice {
    private static final Logger logger = LogManager.getLogger(alice_joye.class);

    public alice_joye() {
        super();
    }

    // Alice has all values WITHOUT the prime
    // In the paper, the server is Alice (has encrypted values), and the client is Bob (has keys)
    public boolean Protocol2(BigInteger x, BigInteger y) throws IOException, HomomorphicException, ClassNotFoundException {
        BigInteger big_m;
        BigInteger u_l;
        BigInteger little_m_l;
        int beta_l;
        int delta_l;

        // Note, we can set a t value.
        // We could enforce that both values have t-bits to enforce timing attack resistance?
        // This assumes that x - y is less than a certain number of bits though...
        // This could be done to enforce u_l has the t-bit set NO MATTER what, so when you mod 2^t
        // you keep that bit there?
        int t;
        BigInteger powT;

        // Compute Big M
        if (isDGK) {
            big_m = DGKOperations.subtract(x, y, dgk_public);
            t = dgk_public.getL();
            u_l = NTL.RandomBnd(dgk_public.getU());
            big_m = DGKOperations.add_plaintext(big_m, u_l, dgk_public);
        }
        else {
            big_m = PaillierCipher.subtract(x, y, paillier_public);
            t = dgk_public.getT();
            u_l = NTL.RandomBnd(paillier_public.getN());
            big_m = PaillierCipher.add_plaintext(big_m, u_l, paillier_public);
        }
        powT = TWO.pow(t);
        little_m_l = u_l.mod(powT);

        // computes delta_l and delta_l_prime
        // In Figure 1, delta_a == delta_l
        writeObject(big_m);
        logger.debug("[private_integer_comparison] Alice is sending {} for Joye Protocol 1 (Embedded)", little_m_l);

        // Complete Protocol 1
        BigInteger [] Encrypted_Y = get_encrypted_bits();
        BigInteger [] XOR = encrypted_xor(little_m_l, Encrypted_Y);
        // Remember that XOR.length is t-bits, x (xor) y is t-bits, so x and y should be t-bits too
        delta_l = compute_delta_a(little_m_l, XOR.length);
        Protocol0(little_m_l, delta_l, XOR, Encrypted_Y);

        // Now that Protocol 1 is done, Bob needs Delta A to compute Delta B
        writeObject(DGKOperations.encrypt(delta_l, dgk_public));

        // Compare values that did NOT get the mod {2^{t}}
        if (u_l.divide(powT).mod(TWO).equals(BigInteger.ZERO)) {
            beta_l = delta_l;
        }
        else {
            beta_l = 1 ^ delta_l;
        }

        /*
         * Unofficial Step 8:
         * Alice has beta_l_prime (which is a delta_a)
         * Bob has beta_l (which is like delta_b)
         * I need the XOR of these, which is done by following steps in decrypt_protocol_1
         * as this gets the other delta, and completes XOR back
         */
        return decrypt_protocol_one(beta_l);
    }

    public boolean Protocol1(BigInteger x) throws HomomorphicException, IOException, ClassNotFoundException {
        BigInteger [] Encrypted_Y = get_encrypted_bits();
        BigInteger [] XOR = encrypted_xor(x, Encrypted_Y);
        // Remember that XOR.length is t-bits, x (xor) y is t-bits, so x and y should be t-bits too
        int delta_a = compute_delta_a(x, XOR.length);
        return Protocol0(x, delta_a, XOR, Encrypted_Y);
    }

    public BigInteger [] compute_c(BigInteger x, BigInteger [] Encrypted_Y,
                                      BigInteger [] XOR, int delta_a, List<Integer> set_l) throws HomomorphicException {

        int first_term;
        BigInteger second_term;
        int set_l_index = 0;

        int xor_bit_length = XOR.length;
        int start_bit_position_x = Math.max(0, xor_bit_length - x.bitLength());
        int start_bit_position_y = Math.max(0, xor_bit_length - Encrypted_Y.length);
        // C has the size floor(t/2) + 1, where 1 is for c_{-1}
        BigInteger [] C = new BigInteger[set_l.size() + 1];

        for (int i = 0; i < XOR.length; i++) {
            BigInteger temp;
            BigInteger sum;
            int x_bit = NTL.bit(x, i - start_bit_position_x);
            BigInteger y_bit;

            if (i >= start_bit_position_y) {
                y_bit = Encrypted_Y[i - start_bit_position_y];
            }
            else {
                y_bit = dgk_public.ZERO(); // If Encrypted_Y is shorter, treat the missing bits as zeros
            }

            if (set_l.contains(i)) {
                // right to left
                // 1 + (1 - 2 * delta_a) * x_i
                first_term = 1 + ((1 - 2 * delta_a) * x_bit);
                // (2 * delta_a - 1) * y_i
                second_term = DGKOperations.multiply(y_bit, (2L * delta_a) - 1, dgk_public);
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
        return C;
    }

    public List<Integer> form_set_l(BigInteger x, int delta_a, BigInteger [] XOR) {
        List<Integer> set_l = new ArrayList<>();
        int floor_t_div_two = (int) Math.floor((float) XOR.length/2);

        // Step 3: Form Set L
        for (int i = 0; i < x.bitLength(); i++) {
            if (delta_a == NTL.bit(x, i)) {
                set_l.add(i);
            }
        }
        logger.debug("delta A = {} and x-bits are {}", delta_a, set_l);

        // I need to confirm that #L = floor(t/2) always
        // This is how I protect against timing attacks.
        for (int i = 0; i < XOR.length; i++) {
            if (set_l.size() == floor_t_div_two) {
                break;
            }
            if (!set_l.contains(i)) {
                set_l.add(i);
            }
        }
        logger.debug("set_l now includes: {}",  set_l);

        // Confirm the value #L = floor(t/2), no more, no less.
        assert floor_t_div_two == set_l.size();
        return set_l;
    }

    // This function is the equivalent of the protocol on Figure 1 on Joye and Salehi's paper
    private boolean Protocol0(BigInteger x, int delta_a, BigInteger [] XOR, BigInteger [] Encrypted_Y)
            throws IOException, ClassNotFoundException, HomomorphicException {

        List<Integer> set_l = form_set_l(x, delta_a, XOR);
        BigInteger [] C = compute_c(x, Encrypted_Y, XOR, delta_a, set_l);
        C = shuffle_bits(C);
        writeObject(C);

        // Get Delta B from Bob
        return decrypt_protocol_one(delta_a);
    }

    public static int compute_delta_a(BigInteger x, int t_bits) throws HomomorphicException {
        // Step 2, Compute Hamming Weight and Select delta A
        int delta_a;
        int hamming_weight = hamming_weight(x);
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

    public static int hamming_weight(BigInteger value) throws HomomorphicException {
        if (value.signum() < 0) {
            throw new HomomorphicException("I'm unsure if Hamming weight is defined for negative");
        }
        else {
            return value.bitCount();
        }
    }
}
