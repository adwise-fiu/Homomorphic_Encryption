package security.paillier;

import java.math.BigInteger;
import java.util.List;

import security.misc.CipherConstants;
import security.misc.HomomorphicException;
import security.misc.NTL;

/**
 * @author Andrew Quijano
 * This class contains the Paillier cipher that supports 
 * Paillier operations on BigIntegers.
 * As it extends from CipherSpi, it can also encrypt byte arrays as well.
 */
public final class PaillierCipher implements CipherConstants {

	//-----------------------BigInteger Paillier----------------------------------------------

	/**
	 * Encrypt with PaillierPublicKey
	 * Compute ciphertext = g^{m}r^{n} (mod n^2)
	 * @param plaintext
	 * @param pk
	 * @return ciphertext
	 * @throws HomomorphicException
	 * 	- If the plaintext is larger than the plaintext supported by Paillier Public Key,
	 * an exception will be thrown
	 */
	public static BigInteger encrypt(BigInteger plaintext, PaillierPublicKey pk)
			throws HomomorphicException 
	{
		if (plaintext.signum() == -1)
		{
			throw new HomomorphicException("Encryption Invalid Parameter: the plaintext is not in Zu (plaintext < 0)"
					+ " value of Plain Text is: " + plaintext);
		}
		else if (plaintext.compareTo(pk.n) >= 0)
		{
			throw new HomomorphicException("Encryption Invalid Parameter: the plaintext is not in N"
					+ " (plaintext >= N) value of Plain Text is: " + plaintext);
		}

		BigInteger randomness = NTL.RandomBnd(pk.n);
		BigInteger tmp1 = pk.g.modPow(plaintext, pk.modulus);
		BigInteger tmp2 = randomness.modPow(pk.n, pk.modulus);
		return NTL.POSMOD(tmp1.multiply(tmp2), pk.modulus);
	}

	public static BigInteger encrypt(long plaintext, PaillierPublicKey pk)
			throws HomomorphicException 
	{
		return PaillierCipher.encrypt(BigInteger.valueOf(plaintext), pk);
	}

	/**
	 * Compute plaintext = L(c^(lambda) mod n^2) * rho mod n
	 * @param ciphertext - Paillier ciphertext
	 * @param sk - used to decrypt ciphertext
	 * @return plaintext
	 * @throws HomomorphicException
	 * 	- If the ciphertext is larger than N^2, an exception will be thrown
	 */
	public static BigInteger decrypt(BigInteger ciphertext, PaillierPrivateKey sk) 
			throws HomomorphicException
	{
		if (ciphertext.signum() == -1) {
			throw new HomomorphicException("decryption Invalid Parameter : the cipher text is not in Zn, "
					+ "value of cipher text is: (c < 0): " + ciphertext);
		}
		else if (ciphertext.compareTo(sk.modulus) > 0) {
			throw new HomomorphicException("decryption Invalid Parameter : the cipher text is not in Zn,"
					+ " value of cipher text is: (c > n): " + ciphertext);
		}
		return L(ciphertext.modPow(sk.lambda, sk.modulus), sk.n).multiply(sk.rho).mod(sk.n);
	}

	/**
	 * returns the sum of the Paillier encrypted values
	 * Note: The result is still encrypted
	 * Warning: If the sum exceeds N, it is subject to N
	 * @param ciphertext1 - Encrypted Paillier value
	 * @param ciphertext2 - Encrypted Paillier value
	 * @param pk - used to encrypt both ciphertexts
	 * @return sum
	 * @throws HomomorphicException 
	 * - If either ciphertext is greater than N or negative, throw an exception
	 */
	public static BigInteger add(BigInteger ciphertext1, BigInteger ciphertext2, PaillierPublicKey pk) 
			throws HomomorphicException
	{
		if (ciphertext1.signum() == -1 || ciphertext1.compareTo(pk.modulus) > 0) {
			throw new HomomorphicException("PaillierAdd Invalid Parameter ciphertext1: " + ciphertext1);
		}
		else if (ciphertext2.signum() == -1 || ciphertext2.compareTo(pk.modulus) > 0) {
			throw new HomomorphicException("PaillierAdd Invalid Parameter ciphertext2: " + ciphertext2);
		}
		return ciphertext1.multiply(ciphertext2).mod(pk.modulus);
	}
	
	/**
	 * returns the sum of the Paillier encrypted value and plaintext value
	 * Warning: If the sum exceeds N, it is subject to mod N
	 * @param ciphertext - Paillier encrypted value
	 * @param plaintext - plaintext value to multiply the ciphertext with
	 * @param pk - was used to encrypt ciphertext
	 * @return Encrypted sum of ciphertext and plaintext
	 * @throws HomomorphicException 
	 * - If a ciphertext is negative or exceeds N^2 or plaintext is negative or exceeds N
	 */
	public static BigInteger add_plaintext(BigInteger ciphertext, BigInteger plaintext, PaillierPublicKey pk) throws HomomorphicException
	{
		if (ciphertext.signum() ==-1 || ciphertext.compareTo(pk.modulus) > 0) {
			throw new HomomorphicException("Paillier add_plaintext Invalid Parameter ciphertext: " + ciphertext);
		}
		// will accept plaintext -1 because of Protocol 1 and Modified Protocol 3 need it
		else if (plaintext.compareTo(NEG_ONE) == -1 || plaintext.compareTo(pk.n) > 0) {
			throw new HomomorphicException("Paillier add_plaintext Invalid Parameter plaintext: " + plaintext);		
		}
		return ciphertext.multiply(pk.g.modPow(plaintext, pk.modulus)).mod(pk.modulus);
	}
	
	/**
	 * Subtract ciphertext1 and ciphertext 2
	 * @param ciphertext1 - Paillier ciphertext
	 * @param ciphertext2 - Paillier ciphertext
	 * @param pk - used to encrypt both ciphertexts
	 * @return Paillier encrypted ciphertext with ciphertext1 - ciphertext2
	 * @throws HomomorphicException 
	 */

	public static BigInteger subtract(BigInteger ciphertext1, BigInteger ciphertext2, PaillierPublicKey pk)
			throws HomomorphicException {
		BigInteger neg_ciphertext2 = multiply(ciphertext2, pk.n.subtract(BigInteger.ONE), pk);
		return ciphertext1.multiply(neg_ciphertext2).mod(pk.modulus);
	}
	
	/**
	 * Computes encrypted Paillier value of the cipher-text subtracted by the plaintext
	 * Warning: If the difference goes negative, add N.
	 * @param ciphertext - Encrypted Paillier value
	 * @param plaintext - plaintext value
	 * @param pk - used to encrypt ciphertext
	 * @return Paillier encrypted ciphertext with ciphertext1 - ciphertext2
	 */
	public static BigInteger subtract_plaintext(BigInteger ciphertext, BigInteger plaintext, PaillierPublicKey pk) {
		return ciphertext.divide(pk.g.modPow(plaintext, pk.modulus)).mod(pk.modulus);
	}
	
	/**
	 * Compute the Paillier encrypted value of ciphertext multiplied by the plaintext.
	 * @param ciphertext - Paillier encrypted value
	 * @param plaintext - plaintext value to multiply the ciphertext with
	 * @param pk - Paillier Public key that encrypted the ciphertext
	 * @return encrypted(ciphertext  plaintext)
	 * @throws HomomorphicException 
	 * If ciphertext is negative or exceeds N^2 or plaintext exceeds N
	 */

	public static BigInteger multiply(BigInteger ciphertext, BigInteger plaintext, PaillierPublicKey pk) throws HomomorphicException
	{
		if (ciphertext.signum() == -1 || ciphertext.compareTo(pk.modulus) > 0) {
			throw new HomomorphicException("PaillierCipher Multiply Invalid Parameter ciphertext: " + ciphertext);
		}
		if(plaintext.signum() == -1 || plaintext.compareTo(pk.n) > 0) {
			throw new HomomorphicException("PaillierCipher Invalid Parameter plaintext: " + plaintext);
		}
		return ciphertext.modPow(plaintext, pk.modulus);
	}

	public static BigInteger multiply(BigInteger ciphertext1, long scalar, PaillierPublicKey pk)
			throws HomomorphicException {
		return multiply(ciphertext1, BigInteger.valueOf(scalar), pk);
	}

	/**
	 * Compute the division of the Paillier cipher-text and a plaintext.
	 * Warning: Divide will only work correctly on perfect divisor like 2|20, it will work.
	 * If you try 3|20, it will NOT work, and you will get a wrong answer!
	 * If you want to do 3|20, you MUST use a division protocol from Veugen paper
	 * @param ciphertext - Paillier ciphertext
	 * @param divisor - plaintext value
	 * @param pk - was used to encrypt ciphertext
	 * @return Encrypted Paillier value equal to ciphertext/plaintext
	 * @throws HomomorphicException 
	 */
	public static BigInteger divide(BigInteger ciphertext, BigInteger divisor, PaillierPublicKey pk)
			throws HomomorphicException {
		return multiply(ciphertext, divisor.modInverse(pk.n), pk);
	}

	/**
	 * L(u) = (u - 1)/n
	 */
	static BigInteger L(BigInteger u, BigInteger n)
	{
		return u.subtract(BigInteger.ONE).divide(n);
	}

	/**
	 * Compute the sum of the encrypted Paillier values
	 * @param values - Array of Encrypted Paillier values 
	 * @param pk - PaillierPublicKey used to encrypt all the values
	 * @return
	 * @throws HomomorphicException
	 */
	public static BigInteger sum(BigInteger [] values, PaillierPublicKey pk)
			throws HomomorphicException {
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		for (BigInteger value : values) {
			sum = PaillierCipher.add(sum, value, pk);
		}
		return sum;
	}
	
	/**
	 * Compute the sum of the encrypted Paillier values
	 * @param values - Array of Encrypted Paillier values
	 * @param pk - PaillierPublicKey used to encrypt the values
	 * @param limit - Sum values up to this index value in the list
	 * @return
	 * @throws HomomorphicException
	 */
	public static BigInteger sum(BigInteger [] values, PaillierPublicKey pk, int limit)
			throws HomomorphicException {
		if (limit > values.length) {
			return sum(values, pk);
		}
		BigInteger sum;
		sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		
		if (limit <= 0) {
			return sum;
		}
		for (int i = 0; i < limit; i++) {
			sum = PaillierCipher.add(sum, values[i], pk);
		}
		return sum;
	}

	/**
	 * Compute the encrypted sum of the list of all Paillier values
	 * @param values - List of Paillier encrypted values by PaillierPublicKey pk
	 * @param pk - PaillierPublicKey used to encrypt every element in values list.
	 * @return Encrypted Paillier sum
	 * @throws HomomorphicException
	 */
	public static BigInteger sum(List<BigInteger> values, PaillierPublicKey pk) 
			throws HomomorphicException
	{
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		for (BigInteger value : values) {
			sum = PaillierCipher.add(sum, value, pk);
		}
		return sum;
	}

	/**
	 * Note: Compute the sum of all values in the list of Paillier Encrypted values.
	 * @param values - List of Encrypted Paillier values
	 * @param pk - PaillierPublicKey used to encrypt the list of values
	 * @param limit - maximum index to sum up to in the area
	 * @return
	 * @throws HomomorphicException
	 */
	public static BigInteger sum(List<BigInteger> values, PaillierPublicKey pk, int limit) 
			throws HomomorphicException {
		if (limit > values.size()) {
			return sum(values, pk);
		}
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		if (limit <= 0) {
			return sum;
		}
		for (int i = 0; i < limit; i++) {
			sum = PaillierCipher.add(sum, values.get(i), pk);
		}
		return sum;
	}

	/**
	 * Compute the sum-product. It computes the scalar multiplication between
	 * the array of Encrypted and plaintext values.
	 * Then it computes the encrypted sum.
	 * @param pk - Paillier Public Key used to encrypt list of ciphertext
	 * @param ciphertext - List of ciphertext
	 * @param plaintext - List of plaintext
	 * @return Encrypted sum product
	 * @throws HomomorphicException
	 * If the lists of encrypted values and plaintext values are not equal
	 */
	public static BigInteger sum_product (List<BigInteger> ciphertext, List<Long> plaintext, PaillierPublicKey pk) 
			throws HomomorphicException {
		if(ciphertext.size() != plaintext.size()) {
			throw new HomomorphicException("Lists are NOT the same size!");
		}

		BigInteger sum = PaillierCipher.encrypt(0, pk);
		BigInteger temp;
		for (int i = 0; i < ciphertext.size(); i++) {
			temp = PaillierCipher.multiply(ciphertext.get(i), plaintext.get(i), pk);
			sum = PaillierCipher.add(temp, sum, pk);
		}
		return sum;
	}
	
	/**
	 * Compute the sum-product. It computes the scalar multiplication between
	 * the array of Encrypted and plaintext values.
	 * Then it computes the encrypted sum.
	 * @param ciphertext - Array of Encrypted Paillier values
	 * @param plaintext - Array of plaintext values
	 * @param pk - Paillier Public Key used to encrypt values in cipher-text list
	 * @return Encrypted sum-product
	 * @throws HomomorphicException
	 * - If the size of plaintext array and ciphertext array isn't equal
	 */
	public static BigInteger sum_product (BigInteger[] ciphertext, Long[] plaintext, PaillierPublicKey pk)
			throws HomomorphicException
	{
		if(ciphertext.length != plaintext.length) {
			throw new HomomorphicException("Arrays are NOT the same size!");
		}

		BigInteger sum = PaillierCipher.encrypt(0, pk);
		BigInteger temp;
		for (int i = 0; i < ciphertext.length; i++) {
			temp = PaillierCipher.multiply(ciphertext[i], plaintext[i], pk);
			sum = PaillierCipher.add(temp, sum, pk);
		}
		return sum;
	}
}