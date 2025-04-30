/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.paillier;

import java.math.BigInteger;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;

/**
 * This class implements the Paillier cryptosystem, which supports homomorphic encryption operations
 * on {@link BigInteger} values. It provides methods for encryption, decryption, addition, subtraction,
 * scalar multiplication, and division (only works under VERY specific circumstances) of encrypted values, as well as utility methods for summation and
 * sum-product calculations.
 *
 * <p>The Paillier cryptosystem is a probabilistic asymmetric encryption scheme that allows
 * homomorphic addition and scalar multiplication of ciphertexts.</p>
 *
 * <p>Note: This class is final and cannot be extended. It implements the {@link CipherConstants} interface.</p>
 *
 * <p>For more details on the Paillier cryptosystem, refer to the original paper by Pascal Paillier:
 * "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes".</p>
 *
 */
public final class PaillierCipher implements CipherConstants {

	private static final Logger logger = LogManager.getLogger(PaillierCipher.class);

	//-----------------------BigInteger Paillier----------------------------------------------

	/**
	 * Encrypts a plaintext using the provided Paillier public key.
	 * The ciphertext is computed as {@code g^m * r^n mod n^2}.
	 *
	 * @param plaintext The plaintext to encrypt as a {@link BigInteger}.
	 * @param public_key The {@link PaillierPublicKey} used for encryption.
	 * @return The encrypted ciphertext as a {@link BigInteger}.
	 * @throws HomomorphicException If the plaintext is negative or exceeds the supported range.
	 */
	public static BigInteger encrypt(BigInteger plaintext, PaillierPublicKey public_key)
			throws HomomorphicException 
	{
		if (plaintext.signum() == -1) {
            logger.warn("Encryption Invalid Parameter: the plaintext is not in Zu (plaintext < 0) value of Plain Text is: {} will be encrypted as {}", plaintext, NTL.POSMOD(plaintext, public_key.getN()));
		}
		else if (plaintext.compareTo(public_key.n) >= 0) {
			throw new HomomorphicException("Encryption Invalid Parameter: the plaintext is not in N"
					+ " (plaintext >= N) value of Plain Text is: " + plaintext);
		}

		BigInteger randomness = NTL.RandomBnd(public_key.n);
		BigInteger tmp1 = public_key.g.modPow(plaintext, public_key.modulus);
		BigInteger tmp2 = randomness.modPow(public_key.n, public_key.modulus);
		return NTL.POSMOD(tmp1.multiply(tmp2), public_key.modulus);
	}

	/**
	 * Encrypts a plaintext represented as a {@code long} using the provided Paillier public key.
	 *
	 * @param plaintext The plaintext to encrypt as a {@code long}.
	 * @param public_key The {@link PaillierPublicKey} used for encryption.
	 * @return The encrypted ciphertext as a {@link BigInteger}.
	 * @throws HomomorphicException If the plaintext is negative or exceeds the supported range.
	 */
	public static BigInteger encrypt(long plaintext, PaillierPublicKey public_key)
			throws HomomorphicException {
		return PaillierCipher.encrypt(BigInteger.valueOf(plaintext), public_key);
	}

	/**
	 * Decrypts a ciphertext using the provided Paillier private key.
	 * The plaintext is computed as {@code L(c^lambda mod n^2) * rho mod n}.
	 *
	 * @param ciphertext The ciphertext to decrypt as a {@link BigInteger}.
	 * @param private_key The {@link PaillierPrivateKey} used for decryption.
	 * @return The decrypted plaintext as a {@link BigInteger}.
	 * @throws HomomorphicException If the ciphertext is negative or exceeds the supported range.
	 */
	public static BigInteger decrypt(BigInteger ciphertext, PaillierPrivateKey private_key) 
			throws HomomorphicException {
		if (ciphertext.signum() == -1) {
			throw new HomomorphicException("decryption Invalid Parameter : the cipher text is not in Zn, "
					+ "value of cipher text is: (c < 0): " + ciphertext);
		}
		else if (ciphertext.compareTo(private_key.modulus) > 0) {
			throw new HomomorphicException("decryption Invalid Parameter : the cipher text is not in Zn,"
					+ " value of cipher text is: (c > n): " + ciphertext);
		}
		return L(ciphertext.modPow(private_key.lambda, private_key.modulus), private_key.n).multiply(private_key.rho).mod(private_key.n);
	}

	/**
	 * Performs homomorphic addition of two Paillier encrypted values.
	 * The result is still encrypted and computed as the product of the two ciphertexts modulo n^2.
	 *
	 * <p>Note: If the sum exceeds n, it is reduced modulo n.</p>
	 *
	 * @param ciphertext1 The first encrypted Paillier value as a {@link BigInteger}.
	 * @param ciphertext2 The second encrypted Paillier value as a {@link BigInteger}.
	 * @param public_key The {@link PaillierPublicKey} used to encrypt both ciphertexts.
	 * @return The encrypted sum of the two ciphertexts as a {@link BigInteger}.
	 * @throws HomomorphicException If either ciphertext is negative or exceeds n^2.
	 */
	public static BigInteger add(BigInteger ciphertext1, BigInteger ciphertext2, PaillierPublicKey public_key) 
			throws HomomorphicException {
		if (ciphertext1.signum() == -1 || ciphertext1.compareTo(public_key.modulus) > 0) {
			throw new HomomorphicException("PaillierAdd Invalid Parameter ciphertext1: " + ciphertext1);
		}
		else if (ciphertext2.signum() == -1 || ciphertext2.compareTo(public_key.modulus) > 0) {
			throw new HomomorphicException("PaillierAdd Invalid Parameter ciphertext2: " + ciphertext2);
		}
		return ciphertext1.multiply(ciphertext2).mod(public_key.modulus);
	}

	/**
	 * Performs homomorphic addition of a Paillier encrypted value and a plaintext value.
	 * The result is encrypted and computed as the product of the ciphertext and g^plaintext modulo n^2.
	 *
	 * <p>Note: If the sum exceeds n, it is reduced modulo n.</p>
	 *
	 * @param ciphertext The encrypted Paillier value as a {@link BigInteger}.
	 * @param plaintext The plaintext value to add as a {@link BigInteger}.
	 * @param public_key The {@link PaillierPublicKey} used to encrypt the ciphertext.
	 * @return The encrypted sum of the ciphertext and plaintext as a {@link BigInteger}.
	 * @throws HomomorphicException If the ciphertext is negative or exceeds n^2, or if the plaintext is negative or exceeds n.
	 */
	public static BigInteger add_plaintext(BigInteger ciphertext, BigInteger plaintext, PaillierPublicKey public_key)
			throws HomomorphicException {
		if (ciphertext.signum() ==-1 || ciphertext.compareTo(public_key.modulus) > 0) {
			throw new HomomorphicException("Paillier add_plaintext Invalid Parameter ciphertext: " + ciphertext);
		}
		// will accept plaintext -1 because of Protocol 1 and Modified Protocol 3 need it
		else if (plaintext.compareTo(NEG_ONE) < 0 || plaintext.compareTo(public_key.n) > 0) {
			throw new HomomorphicException("Paillier add_plaintext Invalid Parameter plaintext: " + plaintext);
		}
		return ciphertext.multiply(public_key.g.modPow(plaintext, public_key.modulus)).mod(public_key.modulus);
	}

	/**
	 * Performs homomorphic subtraction of two Paillier encrypted values.
	 * The result is encrypted and computed as the product of the first ciphertext and the modular inverse of the second ciphertext modulo n^2.
	 *
	 * @param ciphertext1 The first encrypted Paillier value as a {@link BigInteger}.
	 * @param ciphertext2 The second encrypted Paillier value as a {@link BigInteger}.
	 * @param public_key The {@link PaillierPublicKey} used to encrypt both ciphertexts.
	 * @return The encrypted result of ciphertext1 - ciphertext2 as a {@link BigInteger}.
	 * @throws HomomorphicException If either ciphertext is negative or exceeds n^2.
	 */
	public static BigInteger subtract(BigInteger ciphertext1, BigInteger ciphertext2, PaillierPublicKey public_key)
			throws HomomorphicException {
		BigInteger neg_ciphertext2 = multiply(ciphertext2, public_key.n.subtract(BigInteger.ONE), public_key);
		return ciphertext1.multiply(neg_ciphertext2).mod(public_key.modulus);
	}

	/**
	 * Computes the encrypted Paillier value of the ciphertext subtracted by the plaintext.
	 * If the difference is negative, the result is adjusted by adding N.
	 *
	 * @param ciphertext The encrypted Paillier value as a {@link BigInteger}.
	 * @param plaintext The plaintext value to subtract as a {@link BigInteger}.
	 * @param public_key The {@link PaillierPublicKey} used to encrypt the ciphertext.
	 * @return The encrypted result of ciphertext - plaintext as a {@link BigInteger}.
	 * @throws HomomorphicException If an error occurs during the operation.
	 */
	public static BigInteger subtract_plaintext(BigInteger ciphertext, BigInteger plaintext,
												PaillierPublicKey public_key) throws HomomorphicException {
		// Multiply the plaintext value by -1
		BigInteger inverse = NTL.POSMOD(plaintext.multiply(NEG_ONE), public_key.n);
		return add_plaintext(ciphertext, inverse, public_key);
	}

	/**
	 * Computes the encrypted Paillier value of the plaintext subtracted by the ciphertext.
	 * This is equivalent to y - [x] = y + [-x] = [-x] + y.
	 *
	 * @param plaintext The plaintext value to subtract as a {@link BigInteger}.
	 * @param ciphertext The encrypted Paillier value as a {@link BigInteger}.
	 * @param public_key The {@link PaillierPublicKey} used to encrypt the ciphertext.
	 * @return The encrypted result of plaintext - ciphertext as a {@link BigInteger}.
	 * @throws HomomorphicException If an error occurs during the operation.
	 */
	public static BigInteger subtract_ciphertext(BigInteger plaintext, BigInteger ciphertext,
												PaillierPublicKey public_key) throws HomomorphicException {
		// Multiply the ciphertext value by -1
		BigInteger inverse_ciphertext = multiply(ciphertext, public_key.n.subtract(BigInteger.ONE), public_key);
		return add_plaintext(inverse_ciphertext, plaintext, public_key);
	}

	/**
	 * Computes the Paillier encrypted value of a ciphertext multiplied by a plaintext.
	 *
	 * @param ciphertext The Paillier encrypted value as a {@link BigInteger}.
	 * @param plaintext The plaintext value to multiply the ciphertext with as a {@link BigInteger}.
	 * @param public_key The {@link PaillierPublicKey} used to encrypt the ciphertext.
	 * @return The encrypted result of ciphertext * plaintext as a {@link BigInteger}.
	 * @throws HomomorphicException If the ciphertext is negative, exceeds n^2, or if the plaintext is negative or exceeds n.
	 */
	public static BigInteger multiply(BigInteger ciphertext, BigInteger plaintext, PaillierPublicKey public_key)
			throws HomomorphicException {
		if (ciphertext.signum() == -1 || ciphertext.compareTo(public_key.modulus) > 0) {
			throw new HomomorphicException("PaillierCipher Multiply Invalid Parameter ciphertext: " + ciphertext);
		}
		if(plaintext.signum() == -1 || plaintext.compareTo(public_key.n) > 0) {
			throw new HomomorphicException("PaillierCipher Invalid Parameter plaintext: " + plaintext);
		}
		return ciphertext.modPow(plaintext, public_key.modulus);
	}

	/**
	 * Computes the Paillier encrypted value of a ciphertext multiplied by a scalar.
	 *
	 * @param ciphertext1 The Paillier encrypted value as a {@link BigInteger}.
	 * @param scalar The scalar value to multiply the ciphertext with as a {@code long}.
	 * @param public_key The {@link PaillierPublicKey} used to encrypt the ciphertext.
	 * @return The encrypted result of ciphertext * scalar as a {@link BigInteger}.
	 * @throws HomomorphicException If the ciphertext is negative, exceeds n^2, or if the scalar is negative or exceeds n.
	 */
	public static BigInteger multiply(BigInteger ciphertext1, long scalar, PaillierPublicKey public_key)
			throws HomomorphicException {
		return multiply(ciphertext1, BigInteger.valueOf(scalar), public_key);
	}

	/**
	 * Compute the division of the Paillier cipher-text and a plaintext.
	 * Warning: Divide will only work correctly on perfect divisor like 2|20, it will work.
	 * If you try 3|20, it will NOT work, and you will get a wrong answer!
	 * If you want to do 3|20, you MUST use a division protocol from Veugen paper
	 * @param ciphertext - Paillier ciphertext
	 * @param divisor - plaintext value
	 * @param public_key - was used to encrypt ciphertext
	 * @return product - Encrypted Paillier value equal to ciphertext/plaintext
	 * @throws HomomorphicException - If an invalid input was found
     */
	public static BigInteger divide(BigInteger ciphertext, BigInteger divisor, PaillierPublicKey public_key)
			throws HomomorphicException {
		return multiply(ciphertext, divisor.modInverse(public_key.n), public_key);
	}

	/**
	 * Computes the L function used in the Paillier cryptosystem.
	 * The function is defined as L(u) = (u - 1) / n.
	 *
	 * @param u - The input value as a {@link BigInteger}.
	 * @param n - The modulus value as a {@link BigInteger}.
	 * @return The result of the L function as a {@link BigInteger}.
	 */
	static BigInteger L(BigInteger u, BigInteger n) {
		return u.subtract(BigInteger.ONE).divide(n);
	}

	/**
	 * Compute the sum of the encrypted Paillier values
	 * @param values - Array of Encrypted Paillier values 
	 * @param public_key - PaillierPublicKey used to encrypt all the values
	 * @return sum - the encrypted sum of all values in the array
	 * @throws HomomorphicException - If an invalid input was found
     */
	public static BigInteger sum(BigInteger [] values, PaillierPublicKey public_key)
			throws HomomorphicException {
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, public_key);
		for (BigInteger value : values) {
			sum = PaillierCipher.add(sum, value, public_key);
		}
		return sum;
	}
	
	/**
	 * Compute the sum of the encrypted Paillier values
	 * @param values - Array of Encrypted Paillier values
	 * @param public_key - PaillierPublicKey used to encrypt the values
	 * @param limit - Sum values up to this index value in the array
	 * @return sum - the encrypted sum of all values in the array
	 * @throws HomomorphicException - If an invalid input was found
     */
	public static BigInteger sum(BigInteger [] values, PaillierPublicKey public_key, int limit)
			throws HomomorphicException {
		if (limit > values.length) {
			return sum(values, public_key);
		}
		BigInteger sum;
		sum = PaillierCipher.encrypt(BigInteger.ZERO, public_key);
		
		if (limit <= 0) {
			return sum;
		}
		for (int i = 0; i < limit; i++) {
			sum = PaillierCipher.add(sum, values[i], public_key);
		}
		return sum;
	}

	/**
	 * Compute the encrypted sum of all Paillier values
	 * @param values - List of Paillier encrypted values by PaillierPublicKey public_key
	 * @param public_key - PaillierPublicKey used to encrypt every element in values list.
	 * @return sum - the encrypted sum of all values in the list
	 * @throws HomomorphicException - If an invalid input was found
     */
	public static BigInteger sum(List<BigInteger> values, PaillierPublicKey public_key) 
			throws HomomorphicException {
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, public_key);
		for (BigInteger value : values) {
			sum = PaillierCipher.add(sum, value, public_key);
		}
		return sum;
	}

	/**
	 * Note: Compute the sum of all values in the list of Paillier Encrypted values.
	 * @param values - List of Encrypted Paillier values
	 * @param public_key - PaillierPublicKey used to encrypt the list of values
	 * @param limit - maximum index to sum up to in the area
	 * @return sum - the encrypted sum of all values in the list
	 * @throws HomomorphicException - If an invalid input was found
     */
	public static BigInteger sum(List<BigInteger> values, PaillierPublicKey public_key, int limit) 
			throws HomomorphicException {
		if (limit > values.size()) {
			return sum(values, public_key);
		}
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, public_key);
		if (limit <= 0) {
			return sum;
		}
		for (int i = 0; i < limit; i++) {
			sum = PaillierCipher.add(sum, values.get(i), public_key);
		}
		return sum;
	}

	/**
	 * Compute the sum-product. It computes the scalar multiplication between
	 * the array of Encrypted and plaintext values.
	 * Then it computes the encrypted sum.
	 * @param public_key - Paillier Public Key used to encrypt list of ciphertext
	 * @param ciphertext - List of Paillier ciphertext
	 * @param plaintext - List of plaintext
	 * @return Encrypted sum product
	 * @throws HomomorphicException - If the lists of encrypted values and plaintext values are not equal
	 */
	public static BigInteger sum_product (List<BigInteger> ciphertext, List<Long> plaintext, PaillierPublicKey public_key) 
			throws HomomorphicException {
		if(ciphertext.size() != plaintext.size()) {
			throw new HomomorphicException("Lists are NOT the same size!");
		}

		BigInteger sum = PaillierCipher.encrypt(0, public_key);
		BigInteger temp;
		for (int i = 0; i < ciphertext.size(); i++) {
			temp = PaillierCipher.multiply(ciphertext.get(i), plaintext.get(i), public_key);
			sum = PaillierCipher.add(temp, sum, public_key);
		}
		return sum;
	}
	
	/**
	 * Compute the sum-product. It computes the scalar multiplication between
	 * the array of Encrypted and plaintext values.
	 * Then it computes the encrypted sum.
	 * @param ciphertext - Array of Encrypted Paillier values
	 * @param plaintext - Array of plaintext values
	 * @param public_key - Paillier Public Key used to encrypt values in ciphertext list
	 * @return Encrypted sum-product
	 * @throws HomomorphicException - If the size of plaintext array and ciphertext array isn't equal
	 */
	public static BigInteger sum_product (BigInteger[] ciphertext, Long[] plaintext, PaillierPublicKey public_key)
			throws HomomorphicException
	{
		if(ciphertext.length != plaintext.length) {
			throw new HomomorphicException("Arrays are NOT the same size!");
		}

		BigInteger sum = PaillierCipher.encrypt(0, public_key);
		BigInteger temp;
		for (int i = 0; i < ciphertext.length; i++) {
			temp = PaillierCipher.multiply(ciphertext[i], plaintext[i], public_key);
			sum = PaillierCipher.add(temp, sum, public_key);
		}
		return sum;
	}
}