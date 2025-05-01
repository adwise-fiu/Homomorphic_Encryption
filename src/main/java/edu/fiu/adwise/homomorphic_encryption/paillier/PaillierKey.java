/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.paillier;

import java.math.BigInteger;

/**
 * This interface represents a Paillier key used in the Paillier cryptosystem.
 * It provides methods to retrieve the modulus and the value of n.
 */
public interface PaillierKey
{
	/**
	 * Retrieves the value of n, which is part of the Paillier key.
	 *
	 * @return The value of n as a {@link BigInteger}.
	 */
	BigInteger getN();

	/**
	 * Retrieves the modulus used in the Paillier cryptosystem.
	 *
	 * @return The modulus as a {@link BigInteger}.
	 */
	BigInteger getModulus();
}
