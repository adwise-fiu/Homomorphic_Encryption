/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.gm;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

/**
 * This class represents the private key for the Goldwasser-Micali (GM) encryption scheme.
 * It implements the {@link PrivateKey} and {@link GMKey} interfaces and provides access
 * to the private key components \( p \), \( q \), and the modulus \( n \).
 */
public class GMPrivateKey implements Serializable, PrivateKey, GMKey
{
	@Serial
	private static final long serialVersionUID = -6003066379615503599L;
	protected final BigInteger p;
	protected final BigInteger q;
	protected final BigInteger n;


	/**
	 * Constructs a new {@code GMPrivateKey} with the specified prime factors \( p \) and \( q \).
	 * The modulus \( n \) is computed as the product of \( p \) and \( q \).
	 *
	 * @param p The first prime factor of the modulus.
	 * @param q The second prime factor of the modulus.
	 */
	protected GMPrivateKey(BigInteger p, BigInteger q) {
		this.p = p;
		this.q = q;
		this.n = p.multiply(q);
	}

	/**
	 * Returns the algorithm name for this private key.
	 *
	 * @return A string representing the algorithm name, "Goldwasser-Micali".
	 */
	public String getAlgorithm() {
		return "Goldwasser-Micali";
	}

	/**
	 * Returns the format of the encoded key.
	 *
	 * @return A string representing the format, "PKCS#8".
	 */
	public String getFormat() {
		return "PKCS#8";
	}

	/**
	 * Returns the encoded form of the private key.
	 * Currently, this method returns {@code null}.
	 *
	 * @return A byte array representing the encoded key, or {@code null}.
	 */
	public byte[] getEncoded() {
		return null;
	}

	/**
	 * Retrieves the modulus \( n \) associated with this private key.
	 *
	 * @return The modulus \( n \) as a {@link BigInteger}.
	 */
	public BigInteger getN() {
		return this.n;
	}
}
