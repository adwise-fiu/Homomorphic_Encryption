package security.dgk;

import java.math.BigInteger;

import security.misc.CipherConstants;
import security.misc.HomomorphicException;
import security.misc.NTL;


import java.util.List;

public final class DGKOperations implements CipherConstants
{
	//--------------------------------DGK Operations w/ BigInteger----------------------------------

	/**
	 * Encrypt plaintext with DGK Public Key
	 * Compute ciphertext = g^{m}h^{r} (mod n)
	 * @param public_key - use this to encrypt plaintext
	 * @return - DGK ciphertext
	 * throws HomomorphicException
	 * - If the plaintext is larger than the plaintext supported by DGK Public Key,
	 * an exception will be thrown
	 */
	public static BigInteger encrypt(long plaintext, DGKPublicKey public_key)
	{
		BigInteger ciphertext;
		if (plaintext < -1)
		{
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu (plaintext < 0)"
					+ " value of Plain Text is: " + plaintext);
		}
		else if (plaintext >= public_key.u)
		{
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu"
					+ " (plaintext >= U) value of Plain Text is: " + plaintext);
		}

		// If it is null, just fill the HashMap to avoid Null Pointer!
		//first part = g^m (mod n)
		public_key.gLUT.computeIfAbsent(plaintext, p -> public_key.g.modPow(BigInteger.valueOf(p), public_key.n));
		
		// Generate 2 * t bit random number
		BigInteger r = NTL.generateXBitRandom(2 * public_key.t);
		
		// First part = g^m
		BigInteger firstpart = public_key.gLUT.get(plaintext);
		BigInteger secondpart = public_key.h.modPow(r, public_key.n);
		ciphertext = NTL.POSMOD(firstpart.multiply(secondpart), public_key.n);
		return ciphertext;
	}
	
	public static BigInteger encrypt(BigInteger plaintext, DGKPublicKey pk)
	{
		return encrypt(plaintext.longValue(), pk);
	}
	
	/**
	 * Compute DGK decryption
	 * c = g^m * h^r (mod n)
	 * c^vp (mod p) = g^{vp*m} (mod p), Because h^{vp} (mod p) = 1
	 * Use the pre-computed hashmap to retrieve m.
	 * @param private_key - used to decrypt ciphertext
	 * @param ciphertext - DGK ciphertext
	 * @return plaintext
	 */
	public static long decrypt(BigInteger ciphertext, DGKPrivateKey private_key)
	{
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
			throw new IllegalArgumentException("Issue: DGK Public/Private Key mismatch! OR Using non-DGK encrpyted value!");
		}
		return plain;
	}
	
	/**
	 * returns the sum of the Paillier encrypted values
	 * Note: The result is still encrypted
	 * Warning: If the sum exceeds N, it is subject to N
	 * @param ciphertext1 - Encrypted Paillier value
	 * @param ciphertext2 - Encrypted Paillier value
	 * @param pk - used to encrypt both ciphertexts
	 * @throws HomomorphicException
	 * 	- If either ciphertext is greater than N or negative, throw an exception
	 */
	public static BigInteger add(BigInteger ciphertext1, BigInteger ciphertext2, DGKPublicKey pk) 
			throws HomomorphicException
	{
		if (ciphertext1.signum() == -1 || ciphertext1.compareTo(pk.n) > 0) {
			throw new HomomorphicException("DGKAdd Invalid Parameter ciphertext1: " + ciphertext1);
		}
		else if (ciphertext2.signum() == -1 || ciphertext2.compareTo(pk.n) > 0) {
			throw new HomomorphicException("DGKAdd Invalid Parameter ciphertext2: " + ciphertext2);
		}
		return ciphertext1.multiply(ciphertext2).mod(pk.n);
	}
	
	
	/**
	 * returns the sum of the DGK encrypted value and plaintext value
	 * Warning: If the sum exceeds u, it is subject to mod u
	 * @param ciphertext - DGK encrypted value
	 * @param pk - was used to encrypt ciphertext
	 * @return Encrypted sum of ciphertext and plaintext
	 * @throws HomomorphicException 
	 * - If a ciphertext is negative or exceeds N or plaintext is negative or exceeds u
	 */
	public static BigInteger add_plaintext(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey pk) 
			throws HomomorphicException
	{
		if (ciphertext.signum() ==-1 || ciphertext.compareTo(pk.n) > 0) {
			throw new HomomorphicException("DGK add_plaintext Invalid Parameter ciphertext: " + ciphertext);
		}
		// will accept plaintext -1 because of Protocol 1 and Modified Protocol 3 need it
		else if (plaintext.compareTo(NEG_ONE) < 0 || plaintext.compareTo(pk.bigU) > 0) {
			throw new HomomorphicException("DGK  add_plaintext Invalid Parameter plaintext: " + plaintext);		
		}
		return ciphertext.multiply(pk.g.modPow(plaintext, pk.n)).mod(pk.n);
	}
	
	public static BigInteger add_plaintext(BigInteger ciphertext, long plaintext, DGKPublicKey pk) 
			throws HomomorphicException
	{
		return add_plaintext(ciphertext, BigInteger.valueOf(plaintext), pk);
	}

	/**
	 * Subtract ciphertext1 and ciphertext 2
	 * @param pk - used to encrypt both ciphertexts
	 * @return DGK encrypted ciphertext with ciphertext1 - ciphertext2
	 */
	public static BigInteger subtract(BigInteger a, BigInteger b, DGKPublicKey pk) 
			throws HomomorphicException
	{
		BigInteger minus_b = multiply(b, pk.u - 1, pk);
		return add(a, minus_b, pk);
	}
	
	/**
	 * Computes encrypted DGK value of the cipher-text subtractred by the plaintext
	 * Warning: If the difference goes negative, add u.
	 * @param ciphertext - Encrypted DGK value
	 * @param pk - used to encrypt ciphertext
	 * @return DGK encrypted ciphertext with ciphertext1 - ciphertext2
	 */
	public static BigInteger subtract_plaintext(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey pk)
	{
		BigInteger new_ciphertext = ciphertext.divide(pk.g.modPow(plaintext, pk.n)).mod(pk.n);
		return new_ciphertext;
	}

	/**
	 * Compute the DGK encrypted value of ciphertext multiplied by the plaintext.
	 * @param ciphertext - DGK encrypted value
	 * @param pk - DGK Public key the encrypted ciphertext
	 * @throws HomomorphicException
	 * If ciphertext is negative or exceeds N or plaintext exceeds u
	 */
	
	public static BigInteger multiply(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey pk) throws HomomorphicException
	{
		if (ciphertext.signum() == -1 || ciphertext.compareTo(pk.n) > 0) {
			throw new HomomorphicException("DGKMultiply Invalid Parameter ciphertext: " + ciphertext);
		}
		return ciphertext.modPow(plaintext, pk.n);
	}
	
	public static BigInteger multiply(BigInteger cipher, long plaintext, DGKPublicKey pk) 
			throws HomomorphicException {
		return multiply(cipher, BigInteger.valueOf(plaintext), pk);
	}

	/**
	 * Compute the division of the DGK cipher-text and a plaintext.
	 * Warning: Divide will only work correctly on perfect divisor like 2|20, it will work.
	 * If you try 3|20, it will NOT work and you will get a wrong answer!
	 * If you want to do 3|20, you MUST use a division protocol from Veugen paper
	 * @param ciphertext - DGK ciphertext
	 * @param pk - was used to encrypt ciphertext
	 * @return Encrypted DGK value equal to ciphertext/plaintext
	 */
	
	public static BigInteger divide(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey pk) 
			throws HomomorphicException {
		return multiply(ciphertext, plaintext.modInverse(pk.getU()), pk);
	}

	/**
	 * Compute the sum of the encrypted DGK values
	 * @param pk - DGKPublicKey used to encrypt all the values
	 */
	public static BigInteger sum (BigInteger [] parts, DGKPublicKey pk) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, pk);
		for (BigInteger part : parts) {
			sum = add(sum, part, pk);
		}
		return sum;
	}

	/**
	 * Compute the sum of the encrypted DGK values
	 * @param values - Array of Encrypted DGK values
	 * @param pk - DGKPublicKey used to  encrypted the values
	 * @param limit - Sum values up to this index value in the list
	 */
	public static BigInteger sum (BigInteger [] values, DGKPublicKey pk, int limit) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, pk);
		if (limit > values.length) {
			return sum(values, pk);
		}
		else if(limit <= 0) {
			return sum;
		}
		for (int i = 0; i < limit; i++) {
			sum = add(sum, values[i], pk);
		}
		return sum;
	}
	
	/**
	 * Compute the sum of the encrypted DGK values
	 * @param values - List of Encrypted DGK values
	 * @param pk - DGKPublicKey used to  encrypted the values
	 */
	public static BigInteger sum (List<BigInteger> values, DGKPublicKey pk) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, pk);
		for (BigInteger value : values) {
			sum = add(sum, value, pk);
		}
		return sum;
	}
	
	/**
	 * Compute the sum of the encrypted DGK values
	 * @param values - List of Encrypted DGK values
	 * @param pk - DGKPublicKey used to  encrypted the values
	 * @param limit - Sum values up to this index value in the list
	 */
	public static BigInteger sum (List<BigInteger> values, DGKPublicKey pk, int limit) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, pk);
		if (limit > values.size()) {
			return sum(values, pk);
		}
		else if(limit <= 0) {
			return sum;
		}
		for (int i = 0; i < limit; i++) {
			sum = add(sum, values.get(i), pk);
		}
		return sum;
	}
	
	/**
	 * Compute the sum-product. It computes the scalar multiplication between
	 * the array of Encrypted and plaintext values.
	 * Then it computes the encrypted sum.
	 * @param pk - DGK Public Key used to encrypt list of ciphertext
	 * @return DGK Encrypted sum product
	 */
	public static BigInteger sum_product (List<BigInteger> ciphertext, List<Long> plaintext, DGKPublicKey pk) 
			throws HomomorphicException
	{
		if(ciphertext.size() != plaintext.size()) {
			throw new HomomorphicException("Lists are NOT the same size!");
		}
		BigInteger sum = DGKOperations.encrypt(0, pk);
		BigInteger temp;
		for (int i = 0; i < ciphertext.size(); i++) {
			temp = DGKOperations.multiply(ciphertext.get(i), plaintext.get(i), pk);
			sum = DGKOperations.add(temp, sum, pk);
		}
		return sum;
	}
	
	/**
	 * Compute the sum-product. It computes the scalar multiplication between
	 * the array of Encrypted and plaintext values.
	 * Then it computes the encrypted sum.
	 * @param pk - DGK Public Key used to encrypt values in cipher-text list
	 * @return DGK Encrypted sum-product
	 * @throws HomomorphicException
	 * - If the size of plaintext array and ciphertext array isn't equal
	 */
	
	public static BigInteger sum_product (BigInteger[] ciphertext, Long [] plaintext, DGKPublicKey pk)
			throws HomomorphicException
	{
		if(ciphertext.length != plaintext.length) {
			throw new HomomorphicException("Arrays are NOT the same size!");
		}
		
		BigInteger sum = DGKOperations.encrypt(0, pk);
		BigInteger temp;
		for (int i = 0; i < ciphertext.length; i++) {
			temp = DGKOperations.multiply(ciphertext[i], plaintext[i], pk);
			sum = DGKOperations.add(temp, sum, pk);
		}
		return sum;
	}
}