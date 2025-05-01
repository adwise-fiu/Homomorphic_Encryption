/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.elgamal;

import java.math.BigInteger;

import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;

/**
 * This class provides methods for signing and verifying messages using the ElGamal signature scheme.
 * <p>
 * The ElGamal signature scheme is a cryptographic algorithm used for digital signatures.
 * For more details, see <a href="https://en.wikipedia.org/wiki/ElGamal_signature_scheme">ElGamal Signature Scheme</a>.
 * </p>
 */
public class ElGamalSignature implements CipherConstants {
	/**
	 * Signs a message using the ElGamal private key.
	 * <p>
	 * This method generates a digital signature for the given message using the private key.
	 * </p>
	 *
	 * @param message     The plaintext message to be signed.
	 * @param private_key The ElGamal private key used for signing.
	 * @return An {@code ElGamal_Ciphertext} object containing the signature (r, s).
	 */
	public static ElGamal_Ciphertext sign(BigInteger message, ElGamalPrivateKey private_key) {
		BigInteger p1 = private_key.p.subtract(BigInteger.ONE);
		BigInteger K;
		while(true) {
			// Pick [0, p - 2]
			K = NTL.RandomBnd(p1);
			// Need K [2, P - 2]
			if(K.equals(BigInteger.ONE) || K.equals(BigInteger.ZERO)) {
				continue;
			}
			if(K.gcd(p1).equals(BigInteger.ONE)) {
				break;
			}
		}
		BigInteger r = private_key.g.modPow(K, private_key.p);
		BigInteger s = message.subtract(private_key.x.multiply(r)).multiply(K.modInverse(p1)).mod(p1);
		return new ElGamal_Ciphertext(r, s);
	}

	/**
	 * Verifies a signed message using the ElGamal public key.
	 * <p>
	 * This method checks the integrity and authenticity of the signed message.
	 * </p>
	 *
	 * @param message   The plaintext message to verify.
	 * @param signature The signed message to verify, represented as an {@code ElGamal_Ciphertext}.
	 * @param public_key The ElGamal public key used for verification.
	 * @return {@code true} if the signature is valid, {@code false} otherwise.
	 */
	public static boolean verify(BigInteger message, ElGamal_Ciphertext signature, ElGamalPublicKey public_key) {
		BigInteger r = signature.getA();
		BigInteger s = signature.getB();
		BigInteger check;

		if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(public_key.p.subtract(BigInteger.ONE)) > 0) {
			return false;
		}
		if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(public_key.p.subtract(TWO)) > 0) {
			return false;
		}
		// h = y = g^x
		check = public_key.h.modPow(r, public_key.p);
		check = check.multiply(r.modPow(s, public_key.p)).mod(public_key.p);
		return check.compareTo(public_key.g.modPow(message, public_key.p)) == 0;
	}
}
