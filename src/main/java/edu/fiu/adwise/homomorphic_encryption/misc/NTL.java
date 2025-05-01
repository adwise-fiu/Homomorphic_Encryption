/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.misc;

import java.math.BigInteger;

/**
 * This class provides utility methods for cryptographic operations, inspired by the NTL (Number Theory Library).
 * It includes methods for modular arithmetic, random number generation, and mathematical operations
 * such as the Jacobi symbol and quadratic non-residue calculations.
 * <p>
 * This is the Java implementation of the C++ NTL Library
 * Please refer to this site for NTL documentation:
 * <a href="http://www.shoup.net/ntl/doc/tour.html">Tour of C++ NTL</a>
 * <a href="http://www.shoup.net/ntl/doc/ZZ.txt">NTL C++ BigIntegers</a>
 * <p>
 * Credit to Samet Tonyali for helping on revising the code/debugging it.
 */
public final class NTL implements CipherConstants
{
	/**
	 * Computes the positive modulus of a number.
	 *
	 * @param x The dividend as a {@link BigInteger}.
	 * @param n The divisor as a {@link BigInteger}.
	 * @return The positive modulus of {@code x} modulo {@code n}.
	 */
	public static BigInteger POSMOD(BigInteger x, BigInteger n) {
		return x.mod(n).add(n).mod(n);
	}

	/**
	 * Generates a random n-bit positive number.
	 *
	 * @param bits The number of bits for the random number.
	 * @return A {@link BigInteger} representing the n-bit random number.
	 */
	public static BigInteger generateXBitRandom (int bits) {
		if (bits == 0) {
			return BigInteger.ZERO;
		}
		BigInteger r = new BigInteger(bits, rnd);
		r = r.setBit(bits - 1);
		return r;
	}

	/**
	 * Generates a pseudo-random number in the range [0..n-1].
	 *
	 * @param n The upper bound as a {@link BigInteger}.
	 * @return A pseudo-random number in the range [0..n-1], or 0 if {@code n <= 0}.
	 */
	public static BigInteger RandomBnd(BigInteger n) {
		if (n.signum() <= 0) {
			return BigInteger.ZERO;
		}
		BigInteger r;
		do {
			r = new BigInteger(n.bitLength(), rnd);
		}
		while (r.signum()== -1 || r.compareTo(n) >= 0);
		// 0 <= r <= n - 1
		// if r is negative or r >= n, keep generating random numbers
		return r;
	}

	/**
     * Computes the Jacobi symbol (a/n).
     * <a href="https://medium.com/coinmonks/probabilistic-encryption-using-the-goldwasser-micali-gm-method-7f9893a93ac9">Medium article on Goldwasser Micali</a>
     *
     * @param a The numerator as a {@link BigInteger}.
     * @param n The denominator as a {@link BigInteger}.
     * @return The Jacobi symbol as a {@link BigInteger}.
     * @throws IllegalArgumentException If {@code a <= -1} or {@code n} is even.
     */
	public static BigInteger jacobi(BigInteger a, BigInteger n) {
		if (a.compareTo(NEG_ONE) <= 0 || n.mod(TWO).equals(BigInteger.ZERO)) {
			throw new IllegalArgumentException("Invalid value. k = " + a + ", n = " + n);
		}
		a = a.mod(n);
		BigInteger jacobi = BigInteger.ONE;
		while (a.compareTo(BigInteger.ZERO) > 0) {
			while (a.mod(TWO).equals(BigInteger.ZERO)) {
				a = a.divide(TWO);
				BigInteger r = n.mod(EIGHT);
				if (r.equals(THREE) || r.equals(FIVE)) {
					jacobi = jacobi.multiply(NEG_ONE);
				}
			}
			BigInteger temp = n;
			n = a;
			a = temp;
			if (a.mod(FOUR).equals(THREE) && n.mod(FOUR).equals(THREE)) {
				jacobi = jacobi.multiply(NEG_ONE);
			}
			a = a.mod(n);
		}
		if (n.equals(BigInteger.ONE)) {
			return jacobi;
		}
		return BigInteger.ZERO;
	}

	/**
	 * Finds a quadratic non-residue modulo {@code p} and {@code q}.
	 *
	 * @param p A prime number as a {@link BigInteger}.
	 * @param q Another prime number as a {@link BigInteger}.
	 * @return A quadratic non-residue as a {@link BigInteger}.
	 */
	public static BigInteger quadratic_non_residue(BigInteger p, BigInteger q) {
		BigInteger a = NTL.RandomBnd(p);
		while (true) {
			if(NTL.jacobi(a, p).equals(NEG_ONE)) {
				if(NTL.jacobi(a, q).equals(NEG_ONE)) {
					break;
				}
			}
			a = NTL.RandomBnd(p);
		}
		return a;
	}

	/**
	 * Retrieves the bit at position {@code k} of the absolute value of {@code a}.
	 *
	 * @param a The number as a {@link BigInteger}.
	 * @param k The bit position (0-based).
	 * @return The bit value (0 or 1) at position {@code k}, or 0 if {@code k} is out of range.
	 */
	public static int bit(BigInteger a, long k) {
		//If the value k (location of bit is bigger than a
		if (k >= a.bitLength()) {
			return 0;
		}
		if (k < 0) {
			return 0;
		}
		String bit = a.toString(2); // get it in Binary
		if (bit.charAt((int) k)== '0') {
			return 0;
		}
		else {
			return 1;
		}
	}
}