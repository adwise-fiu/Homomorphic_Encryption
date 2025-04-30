/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.gm;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

/**
 * This class represents the public key for the Goldwasser-Micali (GM) encryption scheme.
 * It implements the {@link PublicKey} and {@link GMKey} interfaces and provides access
 * to the public key components \( n \) and \( y \).
 */
public class GMPublicKey implements Serializable, PublicKey, GMKey {
	@Serial
	private static final long serialVersionUID = -235857914395127699L;
	protected final BigInteger n;
	protected final BigInteger y;

	/**
	 * Constructs a new {@code GMPublicKey} with the specified modulus \( n \) and quadratic non-residue \( y \).
	 *
	 * @param n The modulus \( n \), which is the product of two large primes.
	 * @param y A quadratic non-residue modulo \( n \), used in the encryption process.
	 */
	protected GMPublicKey(BigInteger n, BigInteger y) {
		this.n = n;
		this.y = y;
	}

	/**
	 * Returns the algorithm name for this public key.
	 *
	 * @return A string representing the algorithm name, "Goldwasser-Micali".
	 */
	public String getAlgorithm() {
		return "Goldwasser-Micali";
	}

	/**
	 * Returns the format of the encoded key.
	 *
	 * @return A string representing the format, "X.509".
	 */
	public String getFormat() {
		return "X.509";
	}

	/**
	 * Returns the encoded form of the public key.
	 * Currently, this method returns {@code null}.
	 *
	 * @return A byte array representing the encoded key, or {@code null}.
	 */
	public byte[] getEncoded() {
		return null;
	}

	/**
	 * Retrieves the modulus \( n \) associated with this public key.
	 *
	 * @return The modulus \( n \) as a {@link BigInteger}.
	 */
	public BigInteger getN() {
		return this.n;
	}
}
