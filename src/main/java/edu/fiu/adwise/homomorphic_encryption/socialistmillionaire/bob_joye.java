/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.socialistmillionaire;

import edu.fiu.adwise.homomorphic_encryption.dgk.DGKOperations;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierCipher;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Represents Bob's implementation of the Joye and Salehi protocol for secure comparison.
 * This class extends the base `bob` class and provides methods for secure computation
 * using homomorphic encryption schemes such as DGK and Paillier.
 *  See the paper "Private yet Efficient Decision Tree Evaluation"
 *  <a href="https://link.springer.com/content/pdf/10.1007/978-3-319-95729-6_16.pdf">paper link</a>
 */
public class bob_joye extends bob {
    private static final Logger logger = LogManager.getLogger(bob_joye.class);

    /**
     * Constructs a `bob_joye` instance with three key pairs.
     *
     * @param a the first key pair (Paillier or DGK).
     * @param b the second key pair (DGK or Paillier).
     * @param c the third key pair (optional, e.g., ElGamal).
     * @throws IllegalArgumentException if the provided key pairs are invalid or mismatched.
     */
    public bob_joye(KeyPair a, KeyPair b, KeyPair c) throws IllegalArgumentException {
        super(a, b, c);
    }

    /**
     * Constructs a `bob_joye` instance with two key pairs.
     *
     * @param a the first key pair (Paillier or DGK).
     * @param b the second key pair (DGK or Paillier).
     * @throws IllegalArgumentException if the provided key pairs are invalid or mismatched.
     */
    public bob_joye(KeyPair a, KeyPair b) throws IllegalArgumentException {
        super(a, b);
    }

    /**
     * See the paper "Private yet Efficient Decision Tree Evaluation"
     * <a href="https://link.springer.com/content/pdf/10.1007/978-3-319-95729-6_16.pdf">paper link</a>
     *
     * Read Section 3.2 of the paper/Figure 2 for Bob
     * Executes Protocol 2 for secure comparison of encrypted values.
     * This protocol involves multiple steps, including decryption, modular arithmetic,
     * and secure communication with Alice to determine the comparison result.
     *
     * I should note, Protocol1 bob does NOT change from the original DGK or Veugen protocol for Bob, hence no need to
     * reimplement the methods here.
     * @return {@code true} if the comparison result indicates {@code x >= y}, {@code false} otherwise.
     * @throws IOException if an I/O error occurs during communication.
     * @throws ClassNotFoundException if a class cannot be found during deserialization.
     * @throws HomomorphicException if an error occurs during homomorphic operations.
     */
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
