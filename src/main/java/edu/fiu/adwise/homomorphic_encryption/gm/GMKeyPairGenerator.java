/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.gm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;

/**
 * This class is responsible for generating key pairs for the Goldwasser-Micali (GM) encryption scheme.
 * It extends the {@link KeyPairGeneratorSpi} and implements the {@link CipherConstants} interface.
 */
public class GMKeyPairGenerator extends KeyPairGeneratorSpi implements CipherConstants {
	int key_size = KEY_SIZE;

	/**
	 * Initializes the key pair generator with the specified key size and random number generator.
	 *
	 * @param key_size The size of the key to generate (in bits). Must be at least {@code KEY_SIZE}.
	 * @param random   The secure random number generator to use (currently unused in this implementation).
	 * @throws IllegalArgumentException If the key size is less than {@code KEY_SIZE}.
	 */
	public void initialize(int key_size, SecureRandom random) {
		if (key_size < KEY_SIZE) {
			throw new IllegalArgumentException("Minimum strength of 2048 bits required! Safe until 2030...");
		}
		this.key_size = key_size;
	}

	/**
	 * Generates a key pair for the Goldwasser-Micali encryption scheme.
	 *
	 * @return A {@link KeyPair} containing the public and private keys.
	 */
	public KeyPair generateKeyPair() {
		BigInteger p = new BigInteger(key_size/2, CERTAINTY, rnd);
		BigInteger q = new BigInteger(key_size/2, CERTAINTY, rnd);
		// y is a quadratic non-residue modulo n
		BigInteger y = NTL.quadratic_non_residue(p, q);
		BigInteger n = p.multiply(q);
		return new KeyPair(new GMPublicKey(n, y), new GMPrivateKey(p, q));
	}
}
