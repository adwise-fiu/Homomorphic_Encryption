package security.elgamal;

import java.math.BigInteger;

import security.misc.CipherConstants;
import security.misc.NTL;

public class ElGamalSignature implements CipherConstants
{
	/**
	 * Sign a message with ElGamal Private Key
	 * <a href="https://en.wikipedia.org/wiki/ElGamal_signature_scheme">...</a>
	 * @param message - plaintext
	 * @param sk - ElGamal Private Key to sign
	 * @return - signed message
	 */
	public static ElGamal_Ciphertext sign(BigInteger message, ElGamalPrivateKey sk) {
		BigInteger p1 = sk.p.subtract(BigInteger.ONE);
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
		BigInteger r = sk.g.modPow(K, sk.p);
		BigInteger s = message.subtract(sk.x.multiply(r)).multiply(K.modInverse(p1)).mod(p1);
		return new ElGamal_Ciphertext(r, s);
	}
	
	/**
	 * Verify a message with ElGamal Public Key
	 * <a href="https://en.wikipedia.org/wiki/ElGamal_signature_scheme">...</a>
	 * @param message - plaintext
	 * @param signature - signed message to verify
	 * @param pk - Used to verify signed message integrity
	 * @return - true - is valid, false - not valid
	 */
	public static boolean verify(BigInteger message, ElGamal_Ciphertext signature, ElGamalPublicKey pk) {
		BigInteger r = signature.getA();
		BigInteger s = signature.getB();
		BigInteger check;

		if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(pk.p.subtract(BigInteger.ONE)) > 0) {
			//System.err.println("(ElGamal Signature) r: " + r + " and " + pk.p.subtract(BigInteger.ONE));
			return false;
		}
		if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(pk.p.subtract(TWO)) > 0) {
			//System.err.println("(ElGamal Signature) s: " + s + " and " + pk.p.subtract(TWO));
			return false;
		}
		// h = y = g^x
		check = pk.h.modPow(r, pk.p);
		check = check.multiply(r.modPow(s, pk.p)).mod(pk.p);
		return check.compareTo(pk.g.modPow(message, pk.p)) == 0;
	}
}
