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
	 * @param private_key - used to sign message
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

	public static boolean verify(BigInteger message, List<BigInteger> signed_message, PaillierPublicKey public_key) {
		assert signed_message.size() == 2;
		BigInteger sigma_one = signed_message.get(0);
		BigInteger sigma_two = signed_message.get(1);
		return verify(message, sigma_one, sigma_two, public_key);
	}
	
	/**
	 * Verify a Paillier signature
	 * @param message - Plaintext message to verify
	 * @param sigma_one - First component of signature
	 * @param sigma_two - Second component of signature
	 * @param public_key - Used to verify signature
	 * @return - true - valid, false - invalid
	 */
	public static boolean verify(BigInteger message, BigInteger sigma_one, BigInteger sigma_two, PaillierPublicKey public_key) {
		BigInteger first_part = public_key.g.modPow(sigma_one, public_key.modulus);
		BigInteger second_part = sigma_two.modPow(public_key.n, public_key.modulus);
		return message.compareTo(first_part.multiply(second_part).mod(public_key.modulus)) == 0;
	}
}
