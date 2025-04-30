/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.elgamal;

import java.math.BigInteger;

/**
 * Interface representing an ElGamal key.
 */
public interface ElGamal_Key {
	/**
	 * Retrieves the prime modulus \( p \) associated with the key.
	 *
	 * @return the prime modulus \( p \)
	 */
	BigInteger getP();

	/**
	 * Sets whether the key supports additive homomorphism.
	 *
	 * @param additive true if the key supports additive homomorphism, false otherwise
	 */
	void set_additive(boolean additive);
}