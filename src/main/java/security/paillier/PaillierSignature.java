package security.paillier;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

// A guide
//https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/rsa/DigestSignatureSpi.java
public class PaillierSignature {
	
	/**
	 * Please refer to "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes"
	 * @param message to sign
	 * @param sk - used to sign message
	 */
	public static List<BigInteger> sign(BigInteger message, PaillierPrivateKey sk) {
		List<BigInteger> tuple = new ArrayList<>();
		BigInteger sigma_one = PaillierCipher.L(message.modPow(sk.lambda, sk.modulus), sk.n);
		sigma_one = sigma_one.multiply(sk.rho);
		
		BigInteger sigma_two = message.multiply(sk.g.modPow(sigma_one, sk.n).modInverse(sk.n));
		sigma_two = sigma_two.modPow(sk.n.modInverse(sk.lambda), sk.n);
		
		tuple.add(sigma_one);
		tuple.add(sigma_two);
		return tuple;
	}

	public static boolean verify(BigInteger message, List<BigInteger> signed_message, PaillierPublicKey pk) {
		assert signed_message.size() == 2;
		BigInteger sigma_one = signed_message.get(0);
		BigInteger sigma_two = signed_message.get(1);
		return verify(message, sigma_one, sigma_two, pk);
	}
	
	/**
	 * Verify a Paillier signature
	 * @param message - Plaintext message to verify
	 * @param sigma_one - First component of signature
	 * @param sigma_two - Second component of signature
	 * @param pk - Used to verify signature
	 * @return - true - valid, false - invalid
	 */
	public static boolean verify(BigInteger message, BigInteger sigma_one, BigInteger sigma_two, PaillierPublicKey pk) {
		BigInteger first_part = pk.g.modPow(sigma_one, pk.modulus);
		BigInteger second_part = sigma_two.modPow(pk.n, pk.modulus);
		return message.compareTo(first_part.multiply(second_part).mod(pk.modulus)) == 0;
	}
}
