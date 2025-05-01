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

/**
 * Represents Alice's implementation of the Joye and Salehi protocol for secure computation.
 * This class extends the base `alice` class and provides methods for secure comparison
 * and related cryptographic operations using homomorphic encryption.
 * See the paper "Private yet Efficient Decision Tree Evaluation"
 * <a href="https://link.springer.com/content/pdf/10.1007/978-3-319-95729-6_16.pdf">paper link</a>
 */
public class alice_joye extends alice {
    private static final Logger logger = LogManager.getLogger(alice_joye.class);

    /**
     * Default constructor for the `alice_joye` class.
     */
    public alice_joye() {
        super();
    }

    /**
     * Executes Protocol 2 for secure comparison between two encrypted values.
     * This protocol involves multiple steps, including randomization, XOR computation,
     * and secure communication with Bob.
     *
     * @param x the first encrypted value.
     * @param y the second encrypted value.
     * @return {@code true} if {@code x >= y}, {@code false} otherwise.
     * @throws IOException if an I/O error occurs during communication.
     * @throws HomomorphicException if an error occurs during homomorphic operations.
     * @throws ClassNotFoundException if a class cannot be found during deserialization.
     */
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

    /**
     * Executes Protocol 1 for secure comparison of a single unencrypted value with another unencrypted value from Bob.
     * This protocol computes the XOR of the input value with encrypted bits and
     * performs secure communication with Bob.
     *
     * @param x the encrypted value to compare.
     * @return {@code true} if {@code x <= y}, {@code false} otherwise.
     * @throws IOException if an I/O error occurs during communication.
     * @throws HomomorphicException if an error occurs during homomorphic operations.
     * @throws ClassNotFoundException if a class cannot be found during deserialization.
     */
    public boolean Protocol1(BigInteger x) throws HomomorphicException, IOException, ClassNotFoundException {
        BigInteger [] Encrypted_Y = get_encrypted_bits();
        BigInteger [] XOR = encrypted_xor(x, Encrypted_Y);
        // Remember that XOR.length is t-bits, x (xor) y is t-bits, so x and y should be t-bits too
        int delta_a = compute_delta_a(x, XOR.length);
        return Protocol0(x, delta_a, XOR, Encrypted_Y);
    }


    /**
     * Computes the array of encrypted values (C) used in the Joye protocol.
     * This method combines XOR results, encrypted bits, and other parameters
     * to generate the required encrypted values.
     *
     * @param x the plaintext value.
     * @param Encrypted_Y the array of encrypted bits.
     * @param XOR the XOR results of the plaintext and encrypted bits.
     * @param delta_a the delta value for Alice.
     * @param set_l the set of indices used in the computation.
     * @return an array of encrypted values (C).
     * @throws HomomorphicException if an error occurs during homomorphic operations.
     */
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

    /**
     * Forms the set of indices (L) used in the Joye and Salehi protocol.
     * This method ensures that the size of the set matches the required threshold
     * to protect against timing attacks.
     *
     * @param x the plaintext value.
     * @param delta_a the delta value for Alice.
     * @param XOR the XOR results of the plaintext and encrypted bits.
     * @return a list of indices forming the set L.
     */
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

    /**
     * Executes Protocol 0, which is the core of the Joye protocol.
     * This method computes the encrypted values (C), sends them to Bob, and
     * retrieves the result of the secure comparison.
     *
     * @param x the plaintext value.
     * @param delta_a the delta value for Alice.
     * @param XOR the XOR results of the plaintext and encrypted bits.
     * @param Encrypted_Y the array of encrypted bits.
     * @return {@code true} if {@code x <= y}, {@code false} otherwise.
     * @throws IOException if an I/O error occurs during communication.
     * @throws HomomorphicException if an error occurs during homomorphic operations.
     * @throws ClassNotFoundException if a class cannot be found during deserialization.
     */
    private boolean Protocol0(BigInteger x, int delta_a, BigInteger [] XOR, BigInteger [] Encrypted_Y)
            throws IOException, ClassNotFoundException, HomomorphicException {

        List<Integer> set_l = form_set_l(x, delta_a, XOR);
        BigInteger [] C = compute_c(x, Encrypted_Y, XOR, delta_a, set_l);
        C = shuffle_bits(C);
        writeObject(C);

        // Get Delta B from Bob
        return decrypt_protocol_one(delta_a);
    }

    /**
     * Computes the delta value (delta_a) for Alice based on the Hamming weight of the input.
     * This method ensures that the delta value is selected securely and consistently.
     *
     * @param x the plaintext value.
     * @param t_bits the number of bits to consider.
     * @return the computed delta value (delta_a).
     * @throws HomomorphicException if an error occurs during the computation.
     */
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

    /**
     * Computes the Hamming weight of a given value.
     * The Hamming weight is the number of 1 bits in the binary representation of the value.
     *
     * @param value the value whose Hamming weight is to be computed.
     * @return the Hamming weight of the value.
     * @throws HomomorphicException if the value is negative.
     */
    public static int hamming_weight(BigInteger value) throws HomomorphicException {
        if (value.signum() < 0) {
            throw new HomomorphicException("I'm unsure if Hamming weight is defined for negative");
        }
        else {
            return value.bitCount();
        }
    }
}
