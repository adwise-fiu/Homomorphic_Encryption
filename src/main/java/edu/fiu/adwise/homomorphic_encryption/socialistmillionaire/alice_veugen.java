/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.socialistmillionaire;

import edu.fiu.adwise.homomorphic_encryption.dgk.DGKOperations;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierCipher;

import java.io.IOException;
import java.math.BigInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class alice_veugen extends alice {
    private static final Logger logger = LogManager.getLogger(alice_veugen.class);

    public alice_veugen() {
        super();
    }

    /**
     * Please review the bob
     * @param x - plaintext value
     * @return X <= Y
     */
    public boolean Protocol1(BigInteger x) throws ClassNotFoundException, IOException, HomomorphicException {
        return Protocol3(x, rnd.nextInt(2));
    }

    boolean Protocol3(BigInteger x, int deltaA)
            throws ClassNotFoundException, IOException, HomomorphicException {
        if(x.bitLength() > dgk_public.getL()) {
            throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + x.bitLength() + " bits");
        }

        BigInteger [] XOR;
        BigInteger [] C;
        BigInteger [] Encrypted_Y = get_encrypted_bits();

        // Step 2: compute Encrypted X XOR Y
        XOR = encrypted_xor(x, Encrypted_Y);

        // Step 3: delta A is computed on initialization, it is 0 or 1.
        C = new BigInteger [XOR.length + 1];
        int start_bit_position_x = Math.max(0, XOR.length - x.bitLength());
        int start_bit_position_y = Math.max(0, XOR.length - Encrypted_Y.length);

        for (int i = 0; i < XOR.length; i++) {
            // Retrieve corresponding bits from x and Encrypted_Y
            int x_bit;
            BigInteger y_bit;
            x_bit = NTL.bit(x, i - start_bit_position_x);

            if (i >= start_bit_position_y) {
                y_bit = Encrypted_Y[i - start_bit_position_y];
            }
            else {
                y_bit = dgk_public.ZERO(); // If Encrypted_Y is shorter, treat the missing bits as zeros
            }

            // i in L, since bit x_i is equal to delta_A
            if(x_bit == deltaA) {
                C[i] = DGKOperations.sum(XOR, dgk_public, i);
                if (deltaA == 0) {
                    // Step 4 = [1] - [y_i bit] + [c_i]
                    // Step 4 = [c_i] - [y_i bit] + [1]
                    C[i] = DGKOperations.subtract(C[i], y_bit, dgk_public);
                    C[i] = DGKOperations.add_plaintext(C[i], 1, dgk_public);
                }
                else {
                    // Step 4 = [y_i] + [c_i]
                    C[i]= DGKOperations.add(C[i], y_bit, dgk_public);
                }

                // Remember Step 5, blind it.
                C[i] = DGKOperations.multiply(C[i], rnd.nextInt(dgk_public.getL()) + 1, dgk_public);
            }
            // i NOT in L, since bit x_i is NOT equal to delta_A
            else {
                // Skip to Step 5, place a random non-zero number to encrypt
                C[i] = DGKOperations.encrypt(rnd.nextInt(dgk_public.getL()) + 1, dgk_public);
            }
        }

        // This is c_{-1}
        C[XOR.length] = DGKOperations.sum(XOR, dgk_public);
        C[XOR.length] = DGKOperations.add_plaintext(C[XOR.length], deltaA, dgk_public);

        // Shuffle and send bits!
        C = shuffle_bits(C);
        writeObject(C);

        // Run Extra steps to help Alice decrypt Delta
        return decrypt_protocol_one(deltaA);
    }


    /**
     * Primarily used in Protocol 4.
     */
    boolean Modified_Protocol3(BigInteger alpha, BigInteger r, int deltaA)
            throws ClassNotFoundException, IOException, HomomorphicException
    {
        Object in;
        BigInteger [] beta_bits;
        BigInteger [] encAlphaXORBeta;
        BigInteger [] w;
        BigInteger [] C;
        BigInteger alpha_hat;
        BigInteger d;
        BigInteger N;
        long exponent;

        // Get N from the size of Plain-text space
        if(this.isDGK) {
            N = dgk_public.getU();
        }
        else {
            N = paillier_public.getN();
        }

        // Step A: get d from Bob
        in = readObject();
        if (in instanceof BigInteger) {
            d = (BigInteger) in;
        }
        else {
            throw new IllegalArgumentException("Invalid Object received: " + in.getClass().getName());
        }

        beta_bits = get_encrypted_bits();

        // Step C: Alice corrects d...
        if(r.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) < 0) {
            d = DGKOperations.encrypt(BigInteger.ZERO, dgk_public);
        }

        // Step D: Compute alpha_bits XOR beta_bits
        encAlphaXORBeta = encrypted_xor(alpha, beta_bits);

        // Step E: Compute Alpha Hat
        alpha_hat = r.subtract(N).mod(powL);
        w = new BigInteger[encAlphaXORBeta.length];

        int xor_bit_length = encAlphaXORBeta.length;
        int start_bit_position_x = Math.max(0, xor_bit_length - alpha.bitLength());
        int start_bit_position_y = Math.max(0, xor_bit_length - beta_bits.length);
        int start_alpha_hat_position = Math.max(0, xor_bit_length - alpha_hat.bitLength());

        for (int i = 0; i < encAlphaXORBeta.length; i++) {
            int alpha_bit = NTL.bit(alpha, i - start_bit_position_x);
            int alpha_hat_bit = NTL.bit(alpha_hat, i - start_alpha_hat_position);

            if(alpha_hat_bit == alpha_bit) {
                w[i] = encAlphaXORBeta[i];
            }
            else {
                w[i] = DGKOperations.subtract(encAlphaXORBeta[i], d, dgk_public);
            }
        }

        // Step F: See Optimization 1
        for (int i = 0; i < encAlphaXORBeta.length; i++) {
            int alpha_bit = NTL.bit(alpha, i - start_bit_position_x);
            int alpha_hat_bit = NTL.bit(alpha_hat, i - start_alpha_hat_position);

            // If it is 16 or 32 bits...
            if(dgk_public.getL() % 16 == 0) {
                if(alpha_hat_bit != alpha_bit) {
                    w[i] = DGKOperations.multiply(w[i], dgk_public.getL(), dgk_public);
                }
            }
            else {
                BigInteger exponent_i = TWO.pow(i);
                w[i] = DGKOperations.multiply(w[i], exponent_i, dgk_public);
            }
        }

        // Step G: Delta A computed at start!

        // Step H: See Optimization 2
        C = new BigInteger[encAlphaXORBeta.length + 1];

        for (int i = 0; i < encAlphaXORBeta.length; i++) {
            int alpha_bit = NTL.bit(alpha, i - start_bit_position_x);
            int alpha_hat_bit = NTL.bit(alpha_hat, i - start_alpha_hat_position);

            BigInteger beta_bit;
            if (i >= start_bit_position_y) {
                beta_bit = beta_bits[i - start_bit_position_y];
            }
            else {
                beta_bit = dgk_public.ZERO(); // If Encrypted_Y is shorter, treat the missing bits as zeros
            }

            if(deltaA != alpha_bit && deltaA != NTL.bit(alpha_hat, i)) {
                C[i] = dgk_public.ONE;
            }
            else {
                exponent = alpha_hat_bit - alpha_bit;
                C[i] = DGKOperations.multiply(DGKOperations.sum(w, dgk_public, i), 3, dgk_public);
                C[i] = DGKOperations.add_plaintext(C[i], 1 - (2L * deltaA), dgk_public);
                C[i] = DGKOperations.add(C[i], DGKOperations.multiply(d, exponent, dgk_public), dgk_public);
                C[i] = DGKOperations.subtract(C[i], beta_bit, dgk_public);
                C[i] = DGKOperations.add_plaintext(C[i], alpha_bit, dgk_public);
            }
        }

        // This is c_{-1}
        C[encAlphaXORBeta.length] = DGKOperations.sum(encAlphaXORBeta, dgk_public);
        C[encAlphaXORBeta.length] = DGKOperations.add_plaintext(C[encAlphaXORBeta.length], deltaA, dgk_public);

        // Step I: SHUFFLE BITS AND BLIND WITH EXPONENT
        for (int i = 0; i < C.length; i++) {
            C[i] = DGKOperations.multiply(C[i], rnd.nextInt(dgk_public.getU().intValue()) + 1, dgk_public);
        }
        C = shuffle_bits(C);
        writeObject(C);

        // Run Extra steps to help Alice decrypt Delta
        return decrypt_protocol_one(deltaA);
    }

    /**
     *
     * @param x - Encrypted Paillier value OR Encrypted DGK value
     * @param y - Encrypted Paillier value OR Encrypted DGK value
     * @throws IOException - socket errors
     */
    public boolean Protocol2(BigInteger x, BigInteger y)
            throws IOException, ClassNotFoundException, HomomorphicException {
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
        BigInteger N;

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
            N = dgk_public.getU();
        }
        else {
            r = NTL.RandomBnd(paillier_public.getN());
            z = PaillierCipher.add_plaintext(x, r.add(powL).mod(paillier_public.getN()), paillier_public);
            z = PaillierCipher.subtract(z, y, paillier_public);
            N = paillier_public.getN();
        }
        writeObject(z);

        // Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

        // Step 3: alpha = r (mod 2^l)
        alpha = NTL.POSMOD(r, powL);

        // Step 4: Modified Protocol 3 or Protocol 3

        // See Optimization 3: true --> Use Modified Protocol 3
        if(r.add(TWO.pow(dgk_public.getL() + 1)).compareTo(N) < 0) {
            writeBoolean(false);
;
            if(Protocol1(alpha)) {
                x_leq_y = 1;
            }
            else {
                x_leq_y = 0;
            }
        }
        else {
            writeBoolean(true);

            if(Modified_Protocol3(alpha, r, deltaA)) {
                x_leq_y = 1;
            }
            else {
                x_leq_y = 0;
            }
        }

        // Step 5: get Delta B and [[z_1]] and [[z_2]]
        deltaB = deltaA ^ x_leq_y;

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
}
