/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.elgamal;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Represents the private key for the ElGamal encryption scheme.
 * This class implements multiple interfaces to provide functionality for cryptographic operations,
 * serialization, and multithreading.
 *
 * <p>The ElGamalPrivateKey class includes parameters for the private key, as well as the public key
 * components (p, g, h). It also supports additive homomorphic encryption by generating a lookup table
 * for decryption.</p>
 *
 */
public final class ElGamalPrivateKey implements ElGamal_Key, Serializable, PrivateKey, Runnable, CipherConstants {
	@Serial
	private static final long serialVersionUID = 9160045368787508459L;
	private static final Logger logger = LogManager.getLogger(ElGamalPrivateKey.class);
	/** The private key parameter \( x \) used in the ElGamal encryption scheme. */
	final BigInteger x;

	/** The lookup table mapping \( g^m \mod p \) to \( m \) for decryption. */
	final Map<BigInteger, BigInteger> LUT;

	// Taken from ElGamal Public Key
	/** The prime modulus \( p \) used in the ElGamal encryption scheme. */
	final BigInteger p;

	/** The generator \( g \) used in the ElGamal encryption scheme. */
	final BigInteger g;

	/** The public key component \( h \) derived from \( g^x \mod p \). */
	private final BigInteger h;

	/** Indicates whether additive homomorphic encryption is enabled. */
	boolean additive;

	/**
	 * Constructs an ElGamalPrivateKey with the specified parameters.
	 *
	 * @param p        The prime modulus.
	 * @param x        The private key parameter.
	 * @param g        The generator.
	 * @param h        The public key component.
	 * @param additive Whether additive homomorphic encryption is enabled.
	 */
	public ElGamalPrivateKey(BigInteger p, BigInteger x, BigInteger g, BigInteger h, boolean additive) {
		this.p = p;
		this.x = x;
		this.g = g;
		this.h = h;
		this.additive = additive;
		if(additive) {
			this.LUT = new HashMap<>(FIELD_SIZE.intValue(), (float) 1.0);
			this.decrypt_table();
		}
		else {
			this.LUT = null;
		}
	}

	/**
	 * Sets whether additive homomorphic encryption is enabled.
	 *
	 * @param additive True to enable additive homomorphic encryption, false otherwise.
	 */
	public void set_additive(boolean additive) {
		this.additive = additive;
	}

	/**
	 * Returns the algorithm name.
	 *
	 * @return The algorithm name, "ElGamal".
	 */
	public String getAlgorithm()
	{
		return "ElGamal";
	}

	/**
	 * Returns the format of the key.
	 *
	 * @return The format, "PKCS#8".
	 */
	public String getFormat() 
	{
		return "PKCS#8";
	}

	/**
	 * Returns the encoded form of the key.
	 *
	 * @return The encoded key, or null if not supported.
	 */
	public byte[] getEncoded() 
	{
		return null;
	}

	/**
	 * Generates the lookup table for decryption.
	 * The table maps g^m mod p to m for plaintext space [0, p - 1).
	 */
	private void decrypt_table() {
		// Get maximum size of x - y + r + 2^l
		// Assume maximum value is u: biggest value in DGK which is the closest prime from 2^l l = 16 default.
		BigInteger decrypt_size = FIELD_SIZE.add(FIELD_SIZE).subtract(TWO).add(TWO.pow(16));
		long start_time = System.nanoTime();
		logger.info("Building Lookup Table g^m --> m for ElGamal");
		BigInteger message = BigInteger.ZERO;
		while (!message.equals(decrypt_size)) {
			BigInteger gm = this.g.modPow(message, this.p);
			this.LUT.put(gm, message);
			message = message.add(BigInteger.ONE);
		}

		// For negative numbers, go from p - 2 and go down a bit
		message = this.p.subtract(TWO);
		while (!message.equals(this.p.subtract(BigInteger.TEN))) {
			BigInteger gm = this.g.modPow(message, this.p);
			this.LUT.put(gm, message);
			message = message.subtract(BigInteger.ONE);
		}
        logger.info("Finished Building Lookup Table g^m --> m for ElGamal in {} seconds", (System.nanoTime() - start_time) / BigInteger.TEN.pow(9).longValue());
	}

	/**
	 * Runs the decryption table generation in a separate thread.
	 */
	public void run() 
	{
		decrypt_table();
	}

	/**
	 * Returns a string representation of the private key.
	 *
	 * @return A string containing the key parameters.
	 */
	public String toString() {
		String answer = "";
		answer += "p=" + this.p + '\n';
		answer += "g=" + this.g + '\n';
		answer += "h=" + this.h + '\n';
		//answer += "s=" + this.x + '\n';
		return answer;
	}

	/**
	 * Returns the prime modulus p.
	 *
	 * @return The prime modulus p.
	 */
	public BigInteger getP() 
	{
		return this.p;
	}
}
