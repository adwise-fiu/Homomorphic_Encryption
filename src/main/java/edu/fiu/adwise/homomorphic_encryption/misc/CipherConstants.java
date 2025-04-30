/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.misc;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This interface defines constants used across various cryptographic operations,
 * particularly in the context of homomorphic encryption schemes.
 * It includes key sizes, mathematical constants, and utility values.
 */
public interface CipherConstants
{
	/**
	 * The default key size (in bits) for cryptographic operations.
	 */
	int KEY_SIZE = 2048;

	/**
	 * A secure random number generator used for cryptographic purposes.
	 */
	SecureRandom rnd = new SecureRandom();

	/**
	 * The certainty parameter for primality testing algorithms.
	 * It controls the error probability of the primality test.
	 */
	int CERTAINTY = 40;

	/**
	 * The constant value 2, represented as a {@link BigInteger}.
	 * Used in various mathematical operations.
	 */
	BigInteger TWO = new BigInteger("2");

	/**
	 * A prime number with 16 bits, used in ElGamal and DGK encryption schemes.
	 */
	BigInteger FIELD_SIZE = TWO.pow(16).nextProbablePrime();

	/**
	 * The constant value 3, represented as a {@link BigInteger}.
	 * Used in Jacobi symbol calculations.
	 */
	BigInteger THREE = new BigInteger("3");

	/**
	 * The constant value 4, represented as a {@link BigInteger}.
	 * Used in Jacobi symbol calculations.
	 */
	BigInteger FOUR = new BigInteger("4");

	/**
	 * The constant value 5, represented as a {@link BigInteger}.
	 * Used in Jacobi symbol calculations.
	 */
	BigInteger FIVE = new BigInteger("5");

	/**
	 * The constant value 8, represented as a {@link BigInteger}.
	 * Used in Jacobi symbol calculations.
	 */
	BigInteger EIGHT = new BigInteger("8");

	/**
	 * The constant value -1, represented as a {@link BigInteger}.
	 * Used in mathematical operations and Jacobi symbol calculations.
	 */
	BigInteger NEG_ONE = new BigInteger("-1");

	/**
	 * The number of nanoseconds in one second, used for time tracking.
	 */
	int BILLION = BigInteger.TEN.pow(9).intValue();
}