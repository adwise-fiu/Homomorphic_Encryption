package edu.fiu.adwise.homomorphic_encryption.gm;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;

/**
 * This class implements the Goldwasser-Micali (GM) encryption scheme.
 * It provides methods for encrypting, decrypting, and performing XOR operations
 * on encrypted bits using the GM cryptosystem.
 */
public class GMCipher implements CipherConstants
{
	//------------------------------------------Original BigInteger Code----------------------------------------

	/**
	 * Encrypts a BigInteger plaintext using the Goldwasser-Micali encryption scheme.
	 *
	 * @param message    The plaintext message to be encrypted.
	 * @param public_key The public key used for encryption.
	 * @return An array of BigInteger representing the encrypted bits.
	 */
	public static BigInteger [] encrypt(BigInteger message, GMPublicKey public_key) {
		List<BigInteger> enc_bits = new ArrayList<>();
		BigInteger x;
		for(int i = message.bitLength() - 1; i >= 0 ; i--) {
			x = NTL.RandomBnd(public_key.n);
			if(message.testBit(i)) {
				enc_bits.add(public_key.y.multiply(x.modPow(TWO, public_key.n)).mod(public_key.n));
			}
			else {
				enc_bits.add(x.modPow(TWO, public_key.n));
			}
		}
		Collections.reverse(enc_bits);
		return enc_bits.toArray(new BigInteger[0]);
	}

	/**
	 * Decrypts an array of Goldwasser-Micali encrypted bits.
	 *
	 * @param cipher      The array of encrypted bits to be decrypted.
	 * @param private_key The private key used for decryption.
	 * @return The decrypted plaintext as a BigInteger.
	 */
	public static BigInteger decrypt(BigInteger [] cipher, GMPrivateKey private_key) {
		BigInteger e;
		BigInteger m = BigInteger.ZERO;
		for (int i = cipher.length - 1; i >= 0 ; i--) {
			e = NTL.jacobi(cipher[i], private_key.p);
			if (e.equals(NEG_ONE)) {
				m = m.setBit(i);
			}
		}
		return m;
	}

	/**
	 * Performs a bitwise XOR operation on two arrays of Goldwasser-Micali encrypted bits.
	 *
	 * @param cipher_1   The first array of encrypted bits.
	 * @param cipher_2   The second array of encrypted bits.
	 * @param public_key The public key used for encryption.
	 * @return An array of BigInteger representing the XORed encrypted bits.
	 * @throws HomomorphicException If the lengths of the two ciphertext arrays are not equal.
	 */
	public static BigInteger[] xor(BigInteger [] cipher_1, BigInteger[] cipher_2, GMPublicKey public_key) 
			throws HomomorphicException {
		if(cipher_1.length != cipher_2.length) {
			throw new HomomorphicException("Unequal Size of Ciphertext for XOR!");
		}
		BigInteger [] xor_solution = new BigInteger[cipher_1.length];
		for (int i = cipher_1.length - 1; i >= 0 ; i--) {
			xor_solution[i] = cipher_1[i].multiply(cipher_2[i]).mod(public_key.n);
		}
		return xor_solution;
	}
}
