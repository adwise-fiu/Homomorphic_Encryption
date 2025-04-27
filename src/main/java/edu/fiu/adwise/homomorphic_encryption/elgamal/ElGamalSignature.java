package edu.fiu.adwise.homomorphic_encryption.elgamal;

import java.math.BigInteger;

import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;

public class ElGamalSignature implements CipherConstants
{
	/**
	 * Sign a message with ElGamal Private Key
	 * <a href="https://en.wikipedia.org/wiki/ElGamal_signature_scheme">...</a>
	 * @param message - plaintext
	 * @param private_key - ElGamal Private Key to sign
	 * @return - signed message
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
	 * Verify a message with ElGamal Public Key
	 * <a href="https://en.wikipedia.org/wiki/ElGamal_signature_scheme">...</a>
	 * @param message - plaintext
	 * @param signature - signed message to verify
	 * @param public_key - Used to verify signed message integrity
	 * @return - true - is valid, false - not valid
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
