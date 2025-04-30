/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.elgamal;

import java.math.BigInteger;
import java.util.List;

import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;

/**
 * This class provides methods for encryption, decryption, and homomorphic operations
 * using the ElGamal cryptosystem. It supports both additive and multiplicative modes.
 * <p>
 * Reference:
 * <a href="https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/ElGamal.py">...</a>
 */
public class ElGamalCipher {
	/**
	 * Encrypts a plaintext message using the ElGamal public key.
	 *
	 * @param plaintext The plaintext message to encrypt.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The encrypted ciphertext.
	 */
	public static ElGamal_Ciphertext encrypt(BigInteger plaintext, ElGamalPublicKey public_key) {
		if(public_key.additive) {
			return Encrypt_Homomorph(plaintext, public_key);
		}
		else {
			return Encrypt(plaintext, public_key);
		}
	}

	/**
	 * Encrypts a plaintext message (long) using the ElGamal public key.
	 *
	 * @param plaintext The plaintext message to encrypt.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The encrypted ciphertext.
	 */
	public static ElGamal_Ciphertext encrypt(long plaintext, ElGamalPublicKey public_key) {
		BigInteger message = BigInteger.valueOf(plaintext);
		return encrypt(message, public_key);
	}

	/**
	 * Decrypts a ciphertext using the ElGamal private key.
	 *
	 * @param ciphertext The ciphertext to decrypt.
	 * @param private_key The ElGamal private key used for decryption.
	 * @return The decrypted plaintext message.
	 */
	public static BigInteger decrypt(ElGamal_Ciphertext ciphertext, ElGamalPrivateKey private_key) {
		if(private_key.additive) {
			return Decrypt_Homomorph(ciphertext, private_key);	
		}
		else {
			return Decrypt(ciphertext, private_key);	
		}
	}

	/**
	 * Encrypts a plaintext message using the standard ElGamal encryption scheme.
	 *
	 * @param plaintext The plaintext message to encrypt.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The encrypted ciphertext.
	 */
	private static ElGamal_Ciphertext Encrypt(BigInteger plaintext, ElGamalPublicKey public_key) {
		BigInteger pPrime = public_key.p.subtract(BigInteger.ONE).divide(ElGamalKeyPairGenerator.TWO);
		BigInteger r = NTL.RandomBnd(pPrime);
		BigInteger gr = public_key.g.modPow(r, public_key.p);
		BigInteger hrgm = plaintext.multiply(public_key.h.modPow(r, public_key.p)).mod(public_key.p);
		// encrypt couple (g^r (mod p), m * h^r (mod p))
		return new ElGamal_Ciphertext(gr, hrgm);
	}

	/**
	 * Encrypts a plaintext message using the homomorphic ElGamal encryption scheme.
	 *
	 * @param plaintext The plaintext message to encrypt.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The encrypted ciphertext.
	 */
	private static ElGamal_Ciphertext Encrypt_Homomorph(BigInteger plaintext, ElGamalPublicKey public_key) {
		BigInteger pPrime = public_key.p.subtract(BigInteger.ONE).divide(ElGamalKeyPairGenerator.TWO);
		BigInteger r = NTL.RandomBnd(pPrime);
		// encrypt couple (g^r (mod p), h^r * g^m (mod p))
		BigInteger hr = public_key.h.modPow(r, public_key.p);
		BigInteger gm = public_key.g.modPow(plaintext, public_key.p);
		return new ElGamal_Ciphertext(public_key.g.modPow(r, public_key.p), hr.multiply(gm).mod(public_key.p));
	}

	/**
	 * Decrypts a ciphertext using the standard ElGamal decryption scheme.
	 *
	 * @param ciphertext The ciphertext to decrypt.
	 * @param private_key The ElGamal private key used for decryption.
	 * @return The decrypted plaintext message.
	 */
	private static BigInteger Decrypt(ElGamal_Ciphertext ciphertext, ElGamalPrivateKey private_key) {
		BigInteger hr = ciphertext.gr.modPow(private_key.x, private_key.p);
		return ciphertext.hrgm.multiply(hr.modInverse(private_key.p)).mod(private_key.p);
	}

	/**
	 * Decrypts a ciphertext using the homomorphic ElGamal decryption scheme.
	 *
	 * @param ciphertext The ciphertext to decrypt.
	 * @param private_key The ElGamal private key used for decryption.
	 * @return The decrypted plaintext message.
	 */
	private static BigInteger Decrypt_Homomorph(ElGamal_Ciphertext ciphertext, ElGamalPrivateKey private_key) {
		// h^r (mod p) = g^{r * x} (mod p)
		BigInteger hr = ciphertext.gr.modPow(private_key.x, private_key.p);
		// g^m = (h^r * g^m) * (h^r)-1 (mod p) = g^m (mod p)
		BigInteger gm = ciphertext.hrgm.multiply(hr.modInverse(private_key.p)).mod(private_key.p);
		BigInteger m = private_key.LUT.get(gm);

		if (m != null)
		{
			// If I get this, there is a chance I might have a negative number to make?
			if(m.compareTo(private_key.p.subtract(BigInteger.ONE)) >= 0) {
				m = m.mod(private_key.p.subtract(BigInteger.ONE));
				if (m.compareTo(CipherConstants.FIELD_SIZE) > 0) {
					m = m.mod(CipherConstants.FIELD_SIZE);	
				}
			}
			return m;
		}
		else {
			throw new IllegalArgumentException("Entry not found! Key mismatched suspected! Or it is out of scope of u!");
		}
	}

	// --------------BigInteger Homomorphic Operations---------------------------

	/**
	 * Multiplies a ciphertext by a scalar value in additive mode.
	 *
	 * @param ciphertext1 The ciphertext to be multiplied.
	 * @param scalar The scalar value to multiply the ciphertext by.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The resulting ciphertext after multiplication.
	 * @throws IllegalArgumentException If the cipher is in multiplicative mode.
	 */
	public static ElGamal_Ciphertext multiply_scalar(ElGamal_Ciphertext ciphertext1, BigInteger scalar, ElGamalPublicKey public_key) {
		if(public_key.additive) {
			ElGamal_Ciphertext answer;
			answer = new ElGamal_Ciphertext(ciphertext1.gr.modPow(scalar, public_key.p),
					ciphertext1.hrgm.modPow(scalar, public_key.p));
			return answer;
		}
		else {
			throw new IllegalArgumentException("Method is not permitted since ElGamal Cipher is using multiplicative mode!");
		}
	}

	/**
	 * Multiplies a ciphertext by a scalar value (long) in additive mode.
	 *
	 * @param ciphertext1 The ciphertext to be multiplied.
	 * @param scalar The scalar value to multiply the ciphertext by.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The resulting ciphertext after multiplication.
	 */
	public static ElGamal_Ciphertext multiply_scalar(ElGamal_Ciphertext ciphertext1,
													 long scalar, ElGamalPublicKey public_key) {
		return multiply_scalar(ciphertext1, BigInteger.valueOf(scalar), public_key);
	}

	/**
	 * Multiplies two ciphertexts in multiplicative mode.
	 *
	 * @param ciphertext1 The first ciphertext.
	 * @param ciphertext2 The second ciphertext.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The resulting ciphertext after multiplication.
	 * @throws IllegalArgumentException If the cipher is in additive mode.
	 */
	public static ElGamal_Ciphertext multiply(ElGamal_Ciphertext ciphertext1, ElGamal_Ciphertext ciphertext2, ElGamalPublicKey public_key)
	{
		if(public_key.additive) {
			throw new IllegalArgumentException("Method is not permitted since ElGamal Cipher is using additive mode!");			
		}
		else {
			ElGamal_Ciphertext answer;
			answer = new ElGamal_Ciphertext(ciphertext1.gr.multiply(ciphertext2.gr).mod(public_key.p), 
					ciphertext1.hrgm.multiply(ciphertext2.hrgm).mod(public_key.p));
			return answer;	
		}
	}

	/**
	 * Divides one ciphertext by another in multiplicative mode.
	 *
	 * @param ciphertext1 The dividend ciphertext.
	 * @param ciphertext2 The divisor ciphertext.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The resulting ciphertext after division.
	 * @throws IllegalArgumentException If the cipher is in additive mode.
	 */
	public static ElGamal_Ciphertext divide(ElGamal_Ciphertext ciphertext1, ElGamal_Ciphertext ciphertext2, ElGamalPublicKey public_key)
	{
		if(public_key.additive) {
			throw new IllegalArgumentException("Method is not permitted since ElGamal Cipher is using additive mode!");
		}
		else {
			ElGamal_Ciphertext neg_ciphertext2;
			ElGamal_Ciphertext ciphertext;
			// Get mod inverse
			BigInteger inv_gr = ciphertext2.gr.modInverse(public_key.p);
			BigInteger inv_mhr = ciphertext2.hrgm.modInverse(public_key.p);
			neg_ciphertext2 = new ElGamal_Ciphertext(inv_gr, inv_mhr);
			// multiply
			ciphertext = ElGamalCipher.multiply(ciphertext1, neg_ciphertext2, public_key);
			return ciphertext;	
		}
	}

	/**
	 * Adds two ciphertexts in additive mode.
	 *
	 * @param ciphertext1 The first ciphertext.
	 * @param ciphertext2 The second ciphertext.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The resulting ciphertext after addition.
	 * @throws IllegalArgumentException If the cipher is in multiplicative mode.
	 */
	public static ElGamal_Ciphertext add(ElGamal_Ciphertext ciphertext1, ElGamal_Ciphertext ciphertext2, ElGamalPublicKey public_key) {
		if(public_key.additive) {
			ElGamal_Ciphertext answer;
			answer = new ElGamal_Ciphertext(ciphertext1.gr.multiply(ciphertext2.gr).mod(public_key.p), 
					ciphertext1.hrgm.multiply(ciphertext2.hrgm).mod(public_key.p));
			return answer;	
		}
		else {
			throw new IllegalArgumentException("Method is not permitted since ElGamal Cipher is using multiplicative!");
		}
	}

	/**
	 * Subtracts one ciphertext from another in additive mode.
	 *
	 * @param ciphertext1 The ciphertext to subtract from.
	 * @param ciphertext2 The ciphertext to subtract.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The resulting ciphertext after subtraction.
	 * @throws IllegalArgumentException If the cipher is in multiplicative mode.
	 */
	public static ElGamal_Ciphertext subtract(ElGamal_Ciphertext ciphertext1, ElGamal_Ciphertext ciphertext2,
											  ElGamalPublicKey public_key) {
		if(public_key.additive) {
			ElGamal_Ciphertext neg_ciphertext2;
			ElGamal_Ciphertext ciphertext;
			neg_ciphertext2 = ElGamalCipher.multiply_scalar(ciphertext2, -1, public_key);
			ciphertext = ElGamalCipher.add(ciphertext1, neg_ciphertext2, public_key);
			return ciphertext;
		}
		else {
			throw new IllegalArgumentException("Method is not permitted since ElGamal Cipher is using multiplicative!");
		}
	}

	/**
	 * Computes the sum of a list of ciphertexts in additive mode.
	 *
	 * @param values The list of ciphertexts to sum.
	 * @param public_key The ElGamal public key used for encryption.
	 * @param limit The maximum number of ciphertexts to sum.
	 * @return The resulting ciphertext after summation.
	 * @throws HomomorphicException If the cipher is not in additive mode.
	 */
	public static ElGamal_Ciphertext sum(List<ElGamal_Ciphertext> values, ElGamalPublicKey public_key, int limit)
			throws HomomorphicException {

		if (!public_key.additive) {
			throw new HomomorphicException("sum not supported on this version of El Gamal");
		}
		ElGamal_Ciphertext sum = ElGamalCipher.encrypt(BigInteger.ZERO, public_key);
		if (limit <= 0) {
			return sum;
		}
		else if(limit > values.size()) {
			for (ElGamal_Ciphertext value : values) {
				sum = ElGamalCipher.add(sum, value, public_key);
			}
		}
		else {
			for (int i = 0; i < limit; i++) {
				sum = ElGamalCipher.add(sum, values.get(i), public_key);
			}
		}
		return sum;
	}

	/**
	 * Computes the sum of an array of ciphertexts in additive mode.
	 *
	 * @param values The array of ciphertexts to sum.
	 * @param public_key The ElGamal public key used for encryption.
	 * @param limit The maximum number of ciphertexts to sum.
	 * @return The resulting ciphertext after summation.
	 * @throws HomomorphicException If the cipher is not in additive mode.
	 */
	public static ElGamal_Ciphertext sum(ElGamal_Ciphertext [] values, ElGamalPublicKey public_key, int limit)
			throws HomomorphicException {
		if (!public_key.additive) {
			throw new HomomorphicException("sum not supported on this version of El Gamal");
		}

		ElGamal_Ciphertext sum = ElGamalCipher.encrypt(BigInteger.ZERO, public_key);
		if (limit <= 0) {
			return sum;
		}
		else if(limit > values.length) {
			for (ElGamal_Ciphertext value : values) {
				sum = ElGamalCipher.add(sum, value, public_key);
			}
		}
		else {
			for (int i = 0; i < limit; i++) {
				sum = ElGamalCipher.add(sum, values[i], public_key);
			}
		}
		return sum;
	}

	/**
	 * Computes the sum of products of ciphertexts and plaintexts in additive mode.
	 *
	 * @param cipher The array of ciphertexts.
	 * @param plain The array of plaintexts.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The resulting ciphertext after summation of products.
	 * @throws HomomorphicException If the cipher is not in additive mode.
	 * @throws IllegalArgumentException If the arrays are not of the same size.
	 */
	public static ElGamal_Ciphertext sum_product (ElGamal_Ciphertext [] cipher, Long [] plain,
												  ElGamalPublicKey public_key) throws HomomorphicException {
		if (!public_key.additive) {
			throw new HomomorphicException("sum_product not supported on this version of El Gamal");
		}

		if(cipher.length != plain.length) {
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}

		ElGamal_Ciphertext [] product_vector = new ElGamal_Ciphertext[cipher.length];
		for (int i = 0; i < product_vector.length; i++) {
			product_vector[i] = ElGamalCipher.multiply_scalar(cipher[i], plain[i], public_key);
		}
		return ElGamalCipher.sum(product_vector, public_key, product_vector.length);
	}

	/**
	 * Computes the sum of products of the ciphertexts and plaintexts in additive mode.
	 *
	 * @param cipher The list of ciphertexts.
	 * @param plain The list of plaintexts.
	 * @param public_key The ElGamal public key used for encryption.
	 * @return The resulting ciphertext after summation of products.
	 * @throws HomomorphicException If the cipher is not in additive mode.
	 * @throws IllegalArgumentException If the lists are not of the same size.
	 */
	public static ElGamal_Ciphertext sum_product (List<ElGamal_Ciphertext> cipher, List<Long> plain,
												  ElGamalPublicKey public_key) throws HomomorphicException {
		if (!public_key.additive) {
			throw new HomomorphicException("sum_product not supported on this version of El Gamal");
		}

		if(cipher.size() != plain.size()) {
			throw new IllegalArgumentException("Lists are NOT the same size!");
		}

		ElGamal_Ciphertext [] product_vector = new ElGamal_Ciphertext[cipher.size()];
		for (int i = 0; i < product_vector.length; i++) {
			product_vector[i] = ElGamalCipher.multiply_scalar(cipher.get(i), plain.get(i), public_key);
		}
		return ElGamalCipher.sum(product_vector, public_key, product_vector.length);
	}
}
