/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.elgamal;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.util.Random;

import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class is responsible for generating ElGamal key pairs.
 * It supports both additive and multiplicative modes of the ElGamal cryptosystem.
 */
public class ElGamalKeyPairGenerator extends KeyPairGeneratorSpi implements CipherConstants {
	private static final Logger logger = LogManager.getLogger(ElGamalKeyPairGenerator.class);
	private int key_size = KEY_SIZE;
	private SecureRandom random = null;
	private final boolean additive;

	/**
	 * Constructs an ElGamalKeyPairGenerator.
	 *
	 * @param additive Specifies whether the key pair supports additive operations.
	 */
	public ElGamalKeyPairGenerator(boolean additive) {
		this.additive = additive;
	}

	/**
	 * Initializes the key pair generator with the specified key size and random number generator.
	 *
	 * @param key_size The size of the key to generate (in bits).
	 * @param random   The secure random number generator to use.
	 * @throws IllegalArgumentException If the key size is less than half of the default key size.
	 */
	public void initialize(int key_size, SecureRandom random) {
		if (key_size < KEY_SIZE/2) {
			throw new IllegalArgumentException("I am allowing minimum 1024 minimum. Note it isn't safe now though." +
					"This is just to prove my implementation works though...");
		}
		this.key_size = key_size;
		this.random = random;
	}

	/**
	 * Generates an ElGamal key pair.
	 *
	 * @return A {@link KeyPair} containing the public and private keys.
	 */
	public KeyPair generateKeyPair() {
		long start_time;
		if(this.random == null) {
			random = new SecureRandom();
		}
		
		// (a) take a random prime p with getPrime() function. p = 2 * p' + 1 with prime(p') = true
		start_time = System.nanoTime();
		BigInteger p = getPrime(key_size, random);
		logger.info("Obtaining p and q time: " + (System.nanoTime() - start_time)/BILLION + " seconds.");
		
		// (b) take a random element in [Z/Z[p]]* (p' order)
		BigInteger g;
		BigInteger q = p.subtract(BigInteger.ONE).divide(TWO);

		start_time = System.nanoTime();
		while (true) {
			g = NTL.RandomBnd(p);
			g = g.modPow(TWO, p);
			
			if(g.equals(BigInteger.ONE)) {
				continue;
			}
			
			if(g.equals(TWO)) {
				continue;
			}
			
			// Discard g if it divides p-1 because of the attack described
		    // in Note 11.67 (iii) in HAC
			if(p.subtract(BigInteger.ONE).mod(g).equals(BigInteger.ZERO)) {
				continue;
			}
			
			// g^{-1} must not divide p-1 because of Khadir's attack
			// described in "Conditions of the generator for forging ElGamal
			// signature", 2011
			if(!p.subtract(BigInteger.ONE).mod(g.modInverse(p)).equals(BigInteger.ZERO)) {
				break;
			}
		}
		logger.info("Obtaining Generator g time: " + (System.nanoTime() - start_time)/BILLION + " seconds.");
		
		// (c) take x random in [0, p' - 1]
		BigInteger x = NTL.RandomBnd(q);
		BigInteger h = g.modPow(x, p);

		// secret key is (p, x) and public key is (p, g, h)
		ElGamalPrivateKey sk = new ElGamalPrivateKey(p, x, g, h, this.additive);
		ElGamalPublicKey pk = new ElGamalPublicKey(p, g, h, this.additive);
		if (this.additive) {
			logger.info("El-Gamal Key pair generated! (Supports Addition over Ciphertext/Scalar Multiplication");
		}
		else {
			logger.info("El-Gamal Key pair generated! (Supports Multiplication over Ciphertext)");
		}
		return new KeyPair(pk, sk);
	}

	/**
	 * Return a prime p = 2 * p' + 1
	 *
	 * @param nb_bits   is the prime representation
	 * @param prg       random
	 * @return p
	 */
	public static BigInteger getPrime(int nb_bits, Random prg) {
		BigInteger pPrime = new BigInteger(nb_bits, CERTAINTY, prg);
		// p = 2 * pPrime + 1
		BigInteger p = pPrime.multiply(TWO).add(BigInteger.ONE);

		while (!p.isProbablePrime(CERTAINTY)) 
		{
			pPrime = new BigInteger(nb_bits, CERTAINTY, prg);
			p = pPrime.multiply(TWO).add(BigInteger.ONE);
		}
		return p;
	}
}
