package security.elgamal;

import java.math.BigInteger;
import java.util.List;

import security.misc.CipherConstants;
import security.misc.NTL;

// Reference
// https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/ElGamal.py
public class ElGamalCipher
{
	// --------------------------BigInteger ElGamal---------------------------------------
	public static ElGamal_Ciphertext encrypt(BigInteger plaintext, ElGamalPublicKey pk)
	{
		if(pk.ADDITIVE) {
			return Encrypt_Homomorph(plaintext, pk);
		}
		else {
			return Encrypt(plaintext, pk);
		}
	}

	public static ElGamal_Ciphertext encrypt(long plaintext, ElGamalPublicKey pk) {
		BigInteger message = BigInteger.valueOf(plaintext);
		return encrypt(message, pk);
	}

	public static BigInteger decrypt(ElGamal_Ciphertext ciphertext, ElGamalPrivateKey sk)
	{
		if(sk.ADDITIVE) {
			return Decrypt_Homomorph(ciphertext, sk);	
		}
		else {
			return Decrypt(ciphertext, sk);	
		}
	}

	/*
	 * @param (p,g,h) public key
	 * @param message message	
	 */
	private static ElGamal_Ciphertext Encrypt(BigInteger plaintext, ElGamalPublicKey pk)
	{
		BigInteger pPrime = pk.p.subtract(BigInteger.ONE).divide(ElGamalKeyPairGenerator.TWO);
		BigInteger r = NTL.RandomBnd(pPrime);
		BigInteger gr = pk.g.modPow(r, pk.p);
		BigInteger hrgm = plaintext.multiply(pk.h.modPow(r, pk.p)).mod(pk.p);
		// encrypt couple (g^r (mod p), m * h^r (mod p))
		return new ElGamal_Ciphertext(gr, hrgm);
	}

	/*
	 * Encrypt ElGamal homomorphic
	 *
	 * @param (p, g, h) public key
	 * @param message
	 */
	private static ElGamal_Ciphertext Encrypt_Homomorph(BigInteger plaintext, ElGamalPublicKey pk) 
	{
		BigInteger pPrime = pk.p.subtract(BigInteger.ONE).divide(ElGamalKeyPairGenerator.TWO);
		BigInteger r = NTL.RandomBnd(pPrime);
		// encrypt couple (g^r (mod p), h^r * g^m (mod p))
		BigInteger hr = pk.h.modPow(r, pk.p);
		BigInteger gm = pk.g.modPow(plaintext, pk.p);
		return new ElGamal_Ciphertext(pk.g.modPow(r, pk.p), hr.multiply(gm).mod(pk.p));
	}

	/*
	 * Decrypt ElGamal
	 *
	 * @param (p, x) secret key
	 * @param (gr, mhr) = (g^r, m * h^r)
	 * @return the decrypted message
	 */
	private static BigInteger Decrypt(ElGamal_Ciphertext ciphertext, ElGamalPrivateKey sk)
	{
		BigInteger hr = ciphertext.gr.modPow(sk.x, sk.p);
		return ciphertext.hrgm.multiply(hr.modInverse(sk.p)).mod(sk.p);
	}

	/*
	 * @param (p, x) secret key
	 * @param (gr, mhr) = (g^r, h^r * g^m)
	 * @return the decrypted message
	 */
	private static BigInteger Decrypt_Homomorph(ElGamal_Ciphertext ciphertext, ElGamalPrivateKey sk) 
	{
		// h^r (mod p) = g^{r * x} (mod p)
		BigInteger hr = ciphertext.gr.modPow(sk.x, sk.p);
		// g^m = (h^r * g^m) * (h^r)-1 (mod p) = g^m (mod p)
		BigInteger gm = ciphertext.hrgm.multiply(hr.modInverse(sk.p)).mod(sk.p);
		BigInteger m = sk.LUT.get(gm);

		if (m != null)
		{
			// If I get this, there is a chance I might have a negative number to make?
			if(m.compareTo(sk.p.subtract(BigInteger.ONE)) >= 0)
			{
				m = m.mod(sk.p.subtract(BigInteger.ONE));
				if (m.compareTo(CipherConstants.FIELD_SIZE) > 0)
				{
					m = m.mod(CipherConstants.FIELD_SIZE);	
				}
			}
			return m;
		}
		else
		{
			throw new IllegalArgumentException("Entry not found! Key mismatched suspected! Or it is out of scope of u!");
		}
	}

	// --------------BigInteger Homomorphic Operations---------------------------

	public static ElGamal_Ciphertext multiply_scalar(ElGamal_Ciphertext ciphertext1, BigInteger scalar, ElGamalPublicKey pk)
	{
		if(pk.ADDITIVE)
		{
			ElGamal_Ciphertext answer;
			answer = new ElGamal_Ciphertext(ciphertext1.gr.modPow(scalar, pk.p), ciphertext1.hrgm.modPow(scalar, pk.p));
			return answer;
		}
		else
		{
			throw new IllegalArgumentException("Method is not permitted since ElGamal Cipher is using multiplicative mode!");
		}
	}
	
	public static ElGamal_Ciphertext multiply_scalar(ElGamal_Ciphertext ciphertext1, long scalar, ElGamalPublicKey pk)
	{
		return multiply_scalar(ciphertext1, BigInteger.valueOf(scalar), pk);
	}
	
	public static ElGamal_Ciphertext multiply(ElGamal_Ciphertext ciphertext1, ElGamal_Ciphertext ciphertext2, ElGamalPublicKey pk)
	{
		if(pk.ADDITIVE)
		{
			throw new IllegalArgumentException("Method is not permitted since ElGamal Cipher is using additive mode!");			
		}
		else
		{
			ElGamal_Ciphertext answer;
			answer = new ElGamal_Ciphertext(ciphertext1.gr.multiply(ciphertext2.gr).mod(pk.p), 
					ciphertext1.hrgm.multiply(ciphertext2.hrgm).mod(pk.p));
			return answer;	
		}
	}

	public static ElGamal_Ciphertext divide(ElGamal_Ciphertext ciphertext1, ElGamal_Ciphertext ciphertext2, ElGamalPublicKey pk)
	{
		if(pk.ADDITIVE)
		{
			throw new IllegalArgumentException("Method is not permitted since ElGamal Cipher is using additive mode!");
		}
		else
		{
			ElGamal_Ciphertext neg_ciphertext2;
			ElGamal_Ciphertext ciphertext;
			// Get mod inverse
			BigInteger inv_gr = ciphertext2.gr.modInverse(pk.p);
			BigInteger inv_mhr = ciphertext2.hrgm.modInverse(pk.p);
			neg_ciphertext2 = new ElGamal_Ciphertext(inv_gr, inv_mhr);
			// multiply
			ciphertext = ElGamalCipher.multiply(ciphertext1, neg_ciphertext2, pk);
			return ciphertext;	
		}
	}

	public static ElGamal_Ciphertext add(ElGamal_Ciphertext ciphertext1, ElGamal_Ciphertext ciphertext2, ElGamalPublicKey pk)
	{
		if(pk.ADDITIVE)
		{
			ElGamal_Ciphertext answer;
			answer = new ElGamal_Ciphertext(ciphertext1.gr.multiply(ciphertext2.gr).mod(pk.p), 
					ciphertext1.hrgm.multiply(ciphertext2.hrgm).mod(pk.p));
			return answer;	
		}
		else
		{
			throw new IllegalArgumentException("Method is not permitted since ElGamal Cipher is using multiplicative!");
		}
	}

	public static ElGamal_Ciphertext subtract(ElGamal_Ciphertext ciphertext1, ElGamal_Ciphertext ciphertext2, ElGamalPublicKey pk)
	{
		if(pk.ADDITIVE)
		{
			ElGamal_Ciphertext neg_ciphertext2;
			ElGamal_Ciphertext ciphertext;
			neg_ciphertext2 = ElGamalCipher.multiply_scalar(ciphertext2, -1, pk);
			ciphertext = ElGamalCipher.add(ciphertext1, neg_ciphertext2, pk);
			return ciphertext;
		}
		else
		{
			throw new IllegalArgumentException("Method is not permitted since ElGamal Cipher is using multiplicative!");
		}
	}

	public static ElGamal_Ciphertext sum(List<ElGamal_Ciphertext> values, ElGamalPublicKey pk, int limit)
	{
		if (!pk.ADDITIVE) {
			return null;
		}
		ElGamal_Ciphertext sum = ElGamalCipher.encrypt(BigInteger.ZERO, pk);
		if (limit <= 0) {
			return sum;
		}
		else if(limit > values.size()) {
			for (ElGamal_Ciphertext value : values) {
				sum = ElGamalCipher.add(sum, value, pk);
			}
		}
		else
		{
			for (int i = 0; i < limit; i++)
			{
				sum = ElGamalCipher.add(sum, values.get(i), pk);
			}
		}
		return sum;
	}

	public static ElGamal_Ciphertext sum(ElGamal_Ciphertext [] values, ElGamalPublicKey pk, int limit)
	{
		if(pk.ADDITIVE)
		{
			return null;
		}
		ElGamal_Ciphertext sum = ElGamalCipher.encrypt(BigInteger.ZERO, pk);
		if (limit <= 0)
		{
			return sum;
		}
		else if(limit > values.length) {
			for (ElGamal_Ciphertext value : values) {
				sum = ElGamalCipher.add(sum, value, pk);
			}
		}
		else {
			for (int i = 0; i < limit; i++)
			{
				sum = ElGamalCipher.add(sum, values[i], pk);
			}
		}
		return sum;
	}

	public static ElGamal_Ciphertext sum_product (List<ElGamal_Ciphertext> cipher, List<Long> plain, ElGamalPublicKey pk) {
		if(!pk.ADDITIVE) {
			return null;
		}
		if(cipher.size() != plain.size()) {
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}

		ElGamal_Ciphertext [] product_vector = new ElGamal_Ciphertext[cipher.size()];
		for (int i = 0; i < product_vector.length; i++) {
			product_vector[i] = ElGamalCipher.multiply_scalar(cipher.get(i), plain.get(i), pk);
		}
		return ElGamalCipher.sum(product_vector, pk, product_vector.length);
	}

	public static ElGamal_Ciphertext sum_product (List<ElGamal_Ciphertext> cipher, Long [] plain, ElGamalPublicKey pk)
	{
		if(!pk.ADDITIVE) {
			return null;
		}
		if(cipher.size() != plain.length) {
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}

		ElGamal_Ciphertext [] product_vector = new ElGamal_Ciphertext[cipher.size()];
		for (int i = 0; i < product_vector.length; i++) {
			product_vector[i] = ElGamalCipher.multiply_scalar(cipher.get(i), plain[i], pk);
		}
		return ElGamalCipher.sum(product_vector, pk, product_vector.length);
	}
}
