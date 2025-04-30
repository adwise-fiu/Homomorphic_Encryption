package edu.fiu.adwise.homomorphic_encryption.paillier;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * This class provides methods for signing and verifying messages using the Paillier cryptosystem.
 * The Paillier cryptosystem is a probabilistic asymmetric algorithm for public key cryptography.
 * It supports homomorphic encryption and is based on composite degree residuosity classes.
 */
public class PaillierSignature {

	/**
	 * Signs a message using the provided Paillier private key.
	 * The signature consists of two components: sigma\_one and sigma\_two.
	 * Please refer to "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes"
	 * @param message     The message to be signed, represented as a {@link BigInteger}.
	 * @param private_key The {@link PaillierPrivateKey} used to sign the message.
	 * @return A {@link List} of {@link BigInteger} containing the two components of the signature.
	 *         The first element is sigma\_one, and the second element is sigma\_two.
	 */
	public static List<BigInteger> sign(BigInteger message, PaillierPrivateKey private_key) {
		List<BigInteger> tuple = new ArrayList<>();
		BigInteger sigma_one = PaillierCipher.L(message.modPow(private_key.lambda, private_key.modulus), private_key.n);
		sigma_one = sigma_one.multiply(private_key.rho);
		
		BigInteger sigma_two = message.multiply(private_key.g.modPow(sigma_one, private_key.n).modInverse(private_key.n));
		sigma_two = sigma_two.modPow(private_key.n.modInverse(private_key.lambda), private_key.n);
		
		tuple.add(sigma_one);
		tuple.add(sigma_two);
		return tuple;
	}

	/**
	 * Verifies a signed message using the provided Paillier public key.
	 * This method checks the validity of the signature by comparing the computed values
	 * with the original message.
	 *
	 * @param message       The original plaintext message, represented as a {@link BigInteger}.
	 * @param signed_message A {@link List} of {@link BigInteger} containing the signature components.
	 *                       The first element is sigma\_one, and the second element is sigma\_two.
	 * @param public_key    The {@link PaillierPublicKey} used to verify the signature.
	 * @return {@code true} if the signature is valid, {@code false} otherwise.
	 * @throws AssertionError If the signed\_message does not contain exactly two components.
	 */
	public static boolean verify(BigInteger message, List<BigInteger> signed_message, PaillierPublicKey public_key) {
		assert signed_message.size() == 2;
		BigInteger sigma_one = signed_message.get(0);
		BigInteger sigma_two = signed_message.get(1);
		return verify(message, sigma_one, sigma_two, public_key);
	}

	/**
	 * Verifies a Paillier signature using its individual components.
	 * This method computes the expected values of the signature components and compares
	 * them with the provided message.
	 *
	 * @param message    The original plaintext message, represented as a {@link BigInteger}.
	 * @param sigma_one  The first component of the signature.
	 * @param sigma_two  The second component of the signature.
	 * @param public_key The {@link PaillierPublicKey} used to verify the signature.
	 * @return {@code true} if the signature is valid, {@code false} otherwise.
	 */
	public static boolean verify(BigInteger message, BigInteger sigma_one, BigInteger sigma_two, PaillierPublicKey public_key) {
		BigInteger first_part = public_key.g.modPow(sigma_one, public_key.modulus);
		BigInteger second_part = sigma_two.modPow(public_key.n, public_key.modulus);
		return message.compareTo(first_part.multiply(second_part).mod(public_key.modulus)) == 0;
	}
}
