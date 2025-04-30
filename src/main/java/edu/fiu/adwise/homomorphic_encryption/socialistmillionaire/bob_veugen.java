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
import java.security.KeyPair;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * See the papers "Improving the DGK comparison protocol" and Correction to ”Improving the DGK comparison
 * protocol” by Thjis Veugen, You can find these in the papers directory!
 * Represents Bob's implementation of the Veugen protocol for secure comparison.
 * This class extends the base `Bob` class and provides methods for secure computation
 * using homomorphic encryption schemes such as DGK and Paillier.
 */
public class bob_veugen extends bob {
    private static final Logger logger = LogManager.getLogger(bob_veugen.class);

    /**
     * Constructs a `bob_veugen` instance with three key pairs.
     *
     * @param a the first key pair (Paillier or DGK).
     * @param b the second key pair (DGK or Paillier).
     * @param c the third key pair (optional, e.g., ElGamal).
     * @throws IllegalArgumentException if the provided key pairs are invalid or mismatched.
     */
    public bob_veugen(KeyPair a, KeyPair b, KeyPair c) throws IllegalArgumentException {
        super(a, b, c);
    }

    /**
     * Constructs a `bob_veugen` instance with two key pairs.
     *
     * @param a the first key pair (Paillier or DGK).
     * @param b the second key pair (DGK or Paillier).
     * @throws IllegalArgumentException if the provided key pairs are invalid or mismatched.
     */
    public bob_veugen(KeyPair a, KeyPair b) throws IllegalArgumentException {
        super(a, b);
    }

    /**
     * See the paper "Improving the DGK comparison protocol", this implements Protocol 3.
     * This is an improved version of Protocol 1, initially created by DGK, see original bob class
     *
     * This protocol determines if a value `z` is less than `(N - 1) / 2` and securely
     * communicates the result to Alice.
     *
     * @param beta the value to compare.
     * @param z the encrypted value to compare against.
     * @return {@code true} if the comparison result is valid, {@code false} otherwise.
     * @throws IOException if an I/O error occurs during communication.
     * @throws ClassNotFoundException if a class cannot be found during deserialization.
     * @throws IllegalArgumentException if invalid arguments are provided.
     * @throws HomomorphicException if an error occurs during homomorphic operations.
     */
    boolean Modified_Protocol3(BigInteger beta, BigInteger z)
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {

        BigInteger d;
        BigInteger N;

        if(isDGK) {
            N = dgk_public.getU();
        }
        else {
            N = paillier_public.getN();
        }

        // Step A: z < (N - 1)/2
        if(z.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) < 0) {
            d = DGKOperations.encrypt(1, dgk_public);
        }
        else {
            d = DGKOperations.encrypt(0, dgk_public);
        }
        writeObject(d);
        return Protocol1(beta);
    }

    /**
     * See the paper Correction to "Improving the DGK comparison protocol", this implements Protocol 3.
     * This is an improved version of Protocol 1, initially created by DGK, see original bob class
     *
     * This protocol involves multiple steps, including decryption, modular arithmetic,
     * and secure communication with Alice to determine the comparison result.
     *
     * @return {@code true} if the comparison result indicates {@code x >= y}, {@code false} otherwise.
     * @throws IOException if an I/O error occurs during communication.
     * @throws ClassNotFoundException if a class cannot be found during deserialization.
     * @throws HomomorphicException if an error occurs during homomorphic operations.
     * @throws IllegalArgumentException if the protocol constraints are violated.
     */
    public boolean Protocol2()
            throws IOException, ClassNotFoundException, HomomorphicException {
        // Constraint for Paillier
        if(!isDGK && dgk_public.getL() + 2 >= paillier_public.key_size) {
            throw new IllegalArgumentException("Constraint violated: l + 2 < log_2(N)");
        }

        Object x;
        BigInteger beta;
        BigInteger z;
        BigInteger zeta_one;
        BigInteger zeta_two;

        //Step 1: get [[z]] from Alice
        x = readObject();
        if (x instanceof BigInteger) {
            z = (BigInteger) x;
        }
        else {
            throw new IllegalArgumentException("Protocol 4: No BigInteger found! " + x.getClass().getName());
        }

        if(isDGK) {
            z = BigInteger.valueOf(DGKOperations.decrypt(z, dgk_private));
        }
        else {
            z = PaillierCipher.decrypt(z, paillier_private);
        }

        // Step 2: compute Beta = z (mod 2^l),
        beta = NTL.POSMOD(z, powL);

        // Step 3: Alice computes r (mod 2^l) (Alpha)
        // Step 4: Run Modified DGK Comparison Protocol
        // true --> run Modified protocol 3

        if(readBoolean()) {
            if(Modified_Protocol3(beta, z)) {
                logger.info("Modified Protocol 3 selected");
            }
        }
        else {
            Protocol1(beta);
        }

        //Step 5" Send [[z/2^l]], Alice has the solution from Protocol 3 already
        if(isDGK) {
            zeta_one = DGKOperations.encrypt(z.divide(powL), dgk_public);
            if(z.compareTo(dgk_public.getU().subtract(BigInteger.ONE).divide(TWO)) < 0) {
                zeta_two = DGKOperations.encrypt(z.add(dgk_public.getU()).divide(powL), dgk_public);
            }
            else {
                zeta_two = DGKOperations.encrypt(z.divide(powL), dgk_public);
            }
        }
        else
        {
            zeta_one = PaillierCipher.encrypt(z.divide(powL), paillier_public);
            if(z.compareTo(paillier_public.getN().subtract(BigInteger.ONE).divide(TWO)) < 0) {
                zeta_two = PaillierCipher.encrypt(z.add(dgk_public.getN()).divide(powL), paillier_public);
            }
            else {
                zeta_two =  PaillierCipher.encrypt(z.divide(powL), paillier_public);
            }
        }
        writeObject(zeta_one);
        writeObject(zeta_two);

        //Step 6 - 7: Alice Computes [[x >= y]]

        //Step 8 (UNOFFICIAL): Alice needs the answer...
        return decrypt_protocol_two();
    }
}
