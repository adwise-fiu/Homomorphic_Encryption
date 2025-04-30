package edu.fiu.adwise.homomorphic_encryption.dgk;

import java.math.BigInteger;

import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;


import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * DGKOperations is responsible for all the basic DGK functions.
 * Note, we denote x, y as plaintext values and [x] and [y] as the encrypted version of x and y.
 * The functions are:
 * - Encrypt x -> [x]
 * - Decrypt [x] -> x
 * - Add two ciphertexts [x] + [y] -> [x + y]
 * - Add a ciphertext and plaintext [x] + y -> [x + y]
 * - Subtract two ciphertexts [x] - [y] -> [x - y]
 * - Subtract a ciphertext and plaintext [x] - y -> [x - y]
 * - Subtract a plaintext and ciphertext y - [x] -> [y - x]
 * - Multiply a ciphertext and plaintext [x] * y -> [x * y]
 * - Divide a ciphertext by plaintext [x] / y -> [x / y] THIS ONLY WORKS IF YOU KNOW YOU HAVE A PERFECT DIVISOR
 */
public final class DGKOperations implements CipherConstants
{
	private static final Logger logger = LogManager.getLogger(DGKOperations.class);

	//--------------------------------DGK Operations w/ BigInteger----------------------------------

	/**
	 * Encrypt plaintext with DGK Public Key
	 * Compute ciphertext = g^{m}h^{r} (mod n)
	 * @param plaintext - plaintext value to be encrypted
	 * @param public_key - use this to encrypt plaintext
	 * @return - DGK ciphertext of the plaintext
	 * throws HomomorphicException
	 * - If the plaintext is larger than the plaintext supported by DGK Public Key,
	 * an exception will be thrown
	 */
	public static BigInteger encrypt(long plaintext, DGKPublicKey public_key) {
		BigInteger ciphertext;
		if (plaintext < -1) {
            logger.warn("Encryption Invalid Parameter: the plaintext is not in Zu (plaintext < 0) value of Plain Text is: {} will be encrypted as {}", plaintext, NTL.POSMOD(BigInteger.valueOf(plaintext), public_key.getU()));
		}
		else if (plaintext >= public_key.u) {
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu"
					+ " (plaintext >= U) value of Plain Text is: " + plaintext);
		}

		// If it is null, just fill the HashMap to avoid Null Pointer!
		//first part = g^m (mod n)
		public_key.gLUT.computeIfAbsent(plaintext, p -> public_key.g.modPow(BigInteger.valueOf(p), public_key.n));
		
		// Generate 2 * t bit random number
		BigInteger r = NTL.generateXBitRandom(2 * public_key.t);
		
		// First part = g^m
		BigInteger first_part = public_key.gLUT.get(plaintext);
		// Second part = h^r
		BigInteger second_part = public_key.h.modPow(r, public_key.n);
		ciphertext = NTL.POSMOD(first_part.multiply(second_part), public_key.n);
		return ciphertext;
	}
	
	public static BigInteger encrypt(BigInteger plaintext, DGKPublicKey public_key) {
		return encrypt(plaintext.longValue(), public_key);
	}
	
	/**
	 * Compute DGK decryption
	 * c = g^m * h^r (mod n)
	 * c^vp (mod p) = g^{vp*m} (mod p), Because h^{vp} (mod p) = 1
	 * Use the pre-computed hashmap to retrieve m.
	 * @param ciphertext - DGK ciphertext
	 * @param private_key - used to decrypt ciphertext
	 * @return plaintext
	 */
	public static long decrypt(BigInteger ciphertext, DGKPrivateKey private_key) throws HomomorphicException {
		if (ciphertext.signum() == -1) {
			throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn, "
					+ "value of cipher text is: (c < 0): " + ciphertext);
		}
		if(ciphertext.compareTo(private_key.n) > 0) {
			throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn,"
					+ " value of cipher text is: (c > n): " + ciphertext);
		}
		
		BigInteger decipher = NTL.POSMOD(ciphertext.modPow(private_key.vp, private_key.p), private_key.p);
		Long plain = private_key.LUT.get(decipher);
		if(plain == null) {
			throw new HomomorphicException("Issue: DGK Public/Private Key mismatch! OR Using non-DGK encrypted value!");
		}
		return plain;
	}
	
	/**
	 * returns the sum of the two DGK encrypted values
	 * Note: The result is still encrypted
	 * Warning: If the sum exceeds N, it is subject to N
	 * @param ciphertext1 - Encrypted DGK value
	 * @param ciphertext2 - Encrypted DGK value
	 * @param public_key - used to encrypt both ciphertexts
	 * @throws HomomorphicException
	 * 	- If either ciphertext is greater than N or negative, throw an exception
	 */
	public static BigInteger add(BigInteger ciphertext1, BigInteger ciphertext2, DGKPublicKey public_key) 
			throws HomomorphicException
	{
		if (ciphertext1.signum() == -1 || ciphertext1.compareTo(public_key.n) > 0) {
			throw new HomomorphicException("DGKAdd Invalid Parameter ciphertext1: " + ciphertext1);
		}
		else if (ciphertext2.signum() == -1 || ciphertext2.compareTo(public_key.n) > 0) {
			throw new HomomorphicException("DGKAdd Invalid Parameter ciphertext2: " + ciphertext2);
		}
		return ciphertext1.multiply(ciphertext2).mod(public_key.n);
	}
	
	
	/**
	 * returns the sum of the DGK encrypted value and plaintext value
	 * Warning: If the sum exceeds u, it is subject to mod u
	 * @param ciphertext - DGK encrypted value
	 * @param plaintext	- plaintext value
	 * @param public_key - was used to encrypt ciphertext
	 * @return Encrypted sum of ciphertext and plaintext
	 * @throws HomomorphicException 
	 * - If a ciphertext is negative or exceeds N, or plaintext is negative or exceeds u
	 */
	public static BigInteger add_plaintext(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey public_key) 
			throws HomomorphicException
	{
		if (ciphertext.signum() ==-1 || ciphertext.compareTo(public_key.n) > 0) {
			throw new HomomorphicException("DGK add_plaintext Invalid Parameter ciphertext: " + ciphertext);
		}
		// will accept plaintext -1 because of Protocol 1 and Modified Protocol 3 need it
		else if (plaintext.compareTo(NEG_ONE) < 0 || plaintext.compareTo(public_key.bigU) > 0) {
			throw new HomomorphicException("DGK  add_plaintext Invalid Parameter plaintext: " + plaintext);		
		}
		return ciphertext.multiply(public_key.g.modPow(plaintext, public_key.n)).mod(public_key.n);
	}

	/**
	 * returns the sum of the DGK encrypted value and plaintext value
	 * Warning: If the sum exceeds u, it is subject to mod u
	 * @param ciphertext - DGK encrypted value
	 * @param plaintext	- plaintext value
	 * @param public_key - was used to encrypt ciphertext
	 * @return Encrypted sum of ciphertext and plaintext
	 * @throws HomomorphicException
	 * - If a ciphertext is negative or exceeds N, or plaintext is negative or exceeds u
	 */
	public static BigInteger add_plaintext(BigInteger ciphertext, long plaintext, DGKPublicKey public_key) 
			throws HomomorphicException {
		return add_plaintext(ciphertext, BigInteger.valueOf(plaintext), public_key);
	}

	/**
	 * Subtract ciphertext1 and ciphertext 2
	 * @param ciphertext1 - Encrypted DGK value
	 * @param ciphertext2 - Encrypted DGK value
	 * @param public_key - used to encrypt both ciphertexts
	 * @return DGK encrypted ciphertext with ciphertext1 - ciphertext2
	 */
	public static BigInteger subtract(BigInteger ciphertext1, BigInteger ciphertext2, DGKPublicKey public_key) 
			throws HomomorphicException
	{
		BigInteger minus_b = multiply(ciphertext2, public_key.u - 1, public_key);
		return add(ciphertext1, minus_b, public_key);
	}
	
	/**
	 * Computes encrypted DGK value of the cipher-text subtracted by the plaintext
	 * Warning: If the difference goes negative, add u.
	 * @param ciphertext - Encrypted DGK value
	 * @param plaintext - plaintext value
	 * @param public_key - used to encrypt ciphertext
	 * @return DGK encrypted ciphertext with ciphertext1 - ciphertext2
	 */
	public static BigInteger subtract_plaintext(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey public_key)
			throws HomomorphicException {
		BigInteger inverse = NTL.POSMOD(plaintext.multiply(NEG_ONE), public_key.bigU);
		return add_plaintext(ciphertext, inverse, public_key);
	}

	/**
	 * y - [x] = y + [-x] = [-x] + y
	 * Computes encrypted DGK value of the cipher-text subtracted by the plaintext
	 * @param plaintext - plaintext value
	 * @param ciphertext - Encrypted DGK value
	 * @param public_key - used to encrypt ciphertext
	 * @return DGK encrypted ciphertext with plaintext - ciphertext
	 */

	public static BigInteger subtract_ciphertext(BigInteger plaintext, BigInteger ciphertext,
												 DGKPublicKey public_key) throws HomomorphicException {
		// Multiply the ciphertext value by -1
		BigInteger inverse_ciphertext = multiply(ciphertext, public_key.u - 1, public_key);
		return add_plaintext(inverse_ciphertext, plaintext, public_key);
	}

	/**
	 * Compute the DGK encrypted value of ciphertext multiplied by the plaintext.
	 * @param ciphertext - DGK encrypted value
	 * @param plaintext - plaintext value
	 * @param public_key - DGK Public key the encrypted ciphertext
	 * @throws HomomorphicException
	 * If ciphertext is negative or exceeds N or plaintext exceeds u
	 */
	
	public static BigInteger multiply(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey public_key) throws HomomorphicException
	{
		if (ciphertext.signum() == -1 || ciphertext.compareTo(public_key.n) > 0) {
			throw new HomomorphicException("DGKMultiply Invalid Parameter ciphertext: " + ciphertext);
		}
		return ciphertext.modPow(plaintext, public_key.n);
	}

	/**
	 * Compute the DGK encrypted value of ciphertext multiplied by the plaintext.
	 * @param ciphertext - DGK encrypted value
	 * @param plaintext - plaintext value
	 * @param public_key - DGK Public key the encrypted ciphertext
	 * @throws HomomorphicException
	 * If ciphertext is negative or exceeds N or plaintext exceeds u
	 */
	public static BigInteger multiply(BigInteger ciphertext, long plaintext, DGKPublicKey public_key)
			throws HomomorphicException {
		return multiply(ciphertext, BigInteger.valueOf(plaintext), public_key);
	}

	/**
	 * Compute the division of the DGK cipher-text and a plaintext.
	 * Warning: Divide will only work correctly on perfect divisor like 2|20, it will work.
	 * If you try 3|20, it will NOT work, and you will get a wrong answer!
	 * If you want to do 3|20, you MUST use a division protocol from Veugen paper
	 * @param ciphertext - DGK ciphertext
	 * @param plaintext -plaintext value
	 * @param public_key - was used to encrypt ciphertext
	 * @return Encrypted DGK value equal to ciphertext/plaintext
	 */
	
	public static BigInteger divide(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey public_key) 
			throws HomomorphicException {
		return multiply(ciphertext, plaintext.modInverse(public_key.getU()), public_key);
	}

	/**
	 * Compute the sum of the encrypted DGK values
	 * @param parts - Array of Encrypted DGK values
	 * @param public_key - DGKPublicKey used to encrypt all the values
	 */
	public static BigInteger sum (BigInteger [] parts, DGKPublicKey public_key) 
			throws HomomorphicException
	{
		BigInteger sum = public_key.ZERO;
		for (BigInteger part : parts) {
			sum = add(sum, part, public_key);
		}
		return sum;
	}

	/**
	 * Compute the sum of the encrypted DGK values
	 * @param values - Array of Encrypted DGK values
	 * @param public_key - DGKPublicKey used to encrypt the values
	 * @param limit - Sum values up to this index value in the list
	 */
	public static BigInteger sum (BigInteger [] values, DGKPublicKey public_key, int limit) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, public_key);
		if (limit > values.length) {
			return sum(values, public_key);
		}
		else if(limit <= 0) {
			return sum;
		}
		for (int i = 0; i < limit; i++) {
			sum = add(sum, values[i], public_key);
		}
		return sum;
	}
	
	/**
	 * Compute the sum of the encrypted DGK values
	 * @param values - List of Encrypted DGK values
	 * @param public_key - DGKPublicKey used to encrypt the values
	 */
	public static BigInteger sum (List<BigInteger> values, DGKPublicKey public_key) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, public_key);
		for (BigInteger value : values) {
			sum = add(sum, value, public_key);
		}
		return sum;
	}
	
	/**
	 * Compute the sum of the encrypted DGK values
	 * @param values - List of Encrypted DGK values
	 * @param public_key - DGKPublicKey used to encrypt the values
	 * @param limit - Sum values up to this index value in the list
	 */
	public static BigInteger sum (List<BigInteger> values, DGKPublicKey public_key, int limit) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, public_key);
		if (limit > values.size()) {
			return sum(values, public_key);
		}
		else if(limit <= 0) {
			return sum;
		}
		for (int i = 0; i < limit; i++) {
			sum = add(sum, values.get(i), public_key);
		}
		return sum;
	}
	
	/**
	 * Compute the sum-product. It computes the scalar multiplication between
	 * the array of Encrypted and plaintext values.
	 * Then it computes the encrypted sum.
	 * @param ciphertext - List of Encrypted DGK values
	 * @param plaintext - List of Encrypted DGK values
	 * @param public_key - DGK Public Key used to encrypt list of ciphertext
	 * @return DGK Encrypted sum product
	 */
	public static BigInteger sum_product (List<BigInteger> ciphertext, List<Long> plaintext, DGKPublicKey public_key) 
			throws HomomorphicException
	{
		if(ciphertext.size() != plaintext.size()) {
			throw new HomomorphicException("Lists are NOT the same size!");
		}
		BigInteger sum = DGKOperations.encrypt(0, public_key);
		BigInteger temp;
		for (int i = 0; i < ciphertext.size(); i++) {
			temp = DGKOperations.multiply(ciphertext.get(i), plaintext.get(i), public_key);
			sum = DGKOperations.add(temp, sum, public_key);
		}
		return sum;
	}
	
	/**
	 * Compute the sum-product. It computes the scalar multiplication between
	 * the array of Encrypted and plaintext values.
	 * Then it computes the encrypted sum.
	 * @param ciphertext - Array of Encrypted DGK values
	 * @param plaintext - Array of Plaintext values
	 * @param public_key - DGK Public Key used to encrypt values in a ciphertext list
	 * @return DGK Encrypted sum-product
	 * @throws HomomorphicException
	 * - If the size of plaintext array and ciphertext array isn't equal
	 */
	
	public static BigInteger sum_product (BigInteger[] ciphertext, Long [] plaintext, DGKPublicKey public_key)
			throws HomomorphicException
	{
		if(ciphertext.length != plaintext.length) {
			throw new HomomorphicException("Arrays are NOT the same size!");
		}
		
		BigInteger sum = DGKOperations.encrypt(0, public_key);
		BigInteger temp;
		for (int i = 0; i < ciphertext.length; i++) {
			temp = DGKOperations.multiply(ciphertext[i], plaintext[i], public_key);
			sum = DGKOperations.add(temp, sum, public_key);
		}
		return sum;
	}
}