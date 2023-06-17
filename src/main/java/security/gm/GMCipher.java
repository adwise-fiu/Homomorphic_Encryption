package security.gm;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import security.misc.CipherConstants;
import security.misc.HomomorphicException;
import security.misc.NTL;

public class GMCipher implements CipherConstants
{
	//------------------------------------------Original BigInteger Code----------------------------------------
	
	/**
	 * Encrypt a BigInteger plaintext using Goldwasser-Micali
	 * @param message - plaintext message
	 * @param pk - used to encrypt plaintext
	 * @return - Goldwasser-Micali encrypted bits
	 */
	public static List<BigInteger> encrypt(BigInteger message, GMPublicKey pk)
	{
		List<BigInteger> enc_bits = new ArrayList<BigInteger>();  
		BigInteger x;
		for(int i = message.bitLength() - 1; i >= 0 ; i--)
		{
			x = NTL.RandomBnd(pk.n);
			if(message.testBit(i))
			{
				enc_bits.add(pk.y.multiply(x.modPow(TWO, pk.n)).mod(pk.n));
			}
			else
			{
				enc_bits.add(x.modPow(TWO, pk.n));
			}
		}
		Collections.reverse(enc_bits);
		return enc_bits;
	}

	/**
	 * Decrypt Goldwasser-Micali encrypted bits
	 * @param cipher - List of Goldwasser-Micali encrypted bits
	 * @param sk - Goldwasser-Micali Private Key to decrypt
	 */
	public static BigInteger decrypt(List<BigInteger> cipher, GMPrivateKey sk)
	{
		BigInteger e;
		BigInteger m = BigInteger.ZERO;
		for (int i = cipher.size() - 1; i >= 0 ; i--)
		{
			e = NTL.jacobi(cipher.get(i), sk.p);
			if (e.equals(NEG_ONE))
			{
				m = m.setBit(i);
			}
		}
		return m;
	}

	/**
	 * Decrypt Goldwasser-Micali encrypted bits
	 * @param cipher - List of Goldwasser-Micali encrypted bits
	 * @param sk - Goldwasser-Micali Private Key to decrypt
	 */
	public static BigInteger decrypt(BigInteger [] cipher, GMPrivateKey sk)
	{
		BigInteger e;
		BigInteger m = BigInteger.ZERO;
		for (int i = cipher.length - 1; i >= 0 ; i--)
		{
			e = NTL.jacobi(cipher[i], sk.p);
			if (e.equals(NEG_ONE))
			{
				m = m.setBit(i);
			}
		}
		return m;
	}

	/**
	 * XOR the encrypted bits of Goldwasser-Micali
	 * @param cipher_1 - Goldwasser-Micali encrypted ciphertext
	 * @param cipher_2 - Goldwasser-Micali encrypted ciphertext
	 * @param pk - Goldwasser-Micali public key used to encrypt the inputted ciphertexts
	 * @return XORed encrypted ciphertexts
	 */
	public static BigInteger[] xor(BigInteger [] cipher_1, BigInteger[] cipher_2, GMPublicKey pk) 
			throws HomomorphicException
	{
		if(cipher_1.length != cipher_2.length)
		{
			throw new HomomorphicException("Unequal Size of Ciphertext for XOR!");
		}
		BigInteger [] xor_solution = new BigInteger[cipher_1.length];
		for (int i = cipher_1.length - 1; i >= 0 ; i--)
		{
			xor_solution[i] = cipher_1[i].multiply(cipher_2[i]).mod(pk.n);
		}
		return xor_solution;
	}

	// Homomorphic property of GM, multiplying both cipher-texts gets you the bit XOR
	public static BigInteger[] xor(List<BigInteger> cipher_1, List<BigInteger> cipher_2, GMPublicKey pk) 
			throws HomomorphicException
	{
		if(cipher_1.size() != cipher_2.size())
		{
			throw new HomomorphicException("Unequal Size of Ciphertext for XOR!");
		}
		BigInteger [] xor_solution = new BigInteger[cipher_1.size()];
		for (int i = cipher_1.size() - 1; i >= 0 ; i--)
		{
			xor_solution[i] = cipher_1.get(i).multiply(cipher_2.get(i)).mod(pk.n);
		}
		return xor_solution;
	}
}
