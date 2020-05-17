package security.DGK;

import java.math.BigInteger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;

import security.generic.NTL;
import security.paillier.PaillierKey;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;


import java.util.ArrayList;

/*
 * Credits to Andrew Quijano for code conversion and 
 * Samet Tonyali for helping on revising/debugging the library.
 * 
 * DGK was created in 2007 by:
 * Ivan Damgard, Martin Geisler, and Mikkel Kroigaard (DGK).
 * Title of Papers: 
 * Efficient and Secure Comparison for On-Line auctions (2007)
 * A correction to Efficient and Secure Comparison for Online auctions(2009)
 */

public final class DGKOperations extends CipherSpi
{
	protected int stateMode;
	protected Key keyDGK;
	protected SecureRandom SECURE_RANDOM;
	protected int plaintextSize;
	protected int ciphertextSize;
	
	/**
	 * This class support no modes, so engineSetMode() throw exception when
	 * called.
	 */
	protected final void engineSetMode(String mode)
			throws NoSuchAlgorithmException 
	{
		throw new NoSuchAlgorithmException("Paillier supports no modes.");
	}

	/**
	 * This class support no padding, so engineSetPadding() throw exception when
	 * called.
	 */
	protected final void engineSetPadding(String padding)
			throws NoSuchPaddingException 
	{
		throw new NoSuchPaddingException("Paillier supports no padding.");
	}

	/**
	 * Perform actual encryption ,creates single array and updates the result
	 * after the encryption.
	 * 
	 * @param input
	 *            - the input in bytes
	 * @param inputOffset
	 *            - the offset in input where the input starts always zero
	 * @param inputLenth
	 *            - the input length
	 * @param output
	 *            - the buffer for the result
	 * @param outputOffset
	 *            - the offset in output where the result is stored
	 * @return the number of bytes stored in output
	 * @throws Exception
	 *             throws if Plaintext m is not in Z_n , m should be less then n
	 */
	protected final int encrypt(byte[] input, int inputOffset, int inputLenth,
			byte[] output, int outputOffset) throws Exception
	{
		BigInteger m = new BigInteger(input);

		// get the public key in order to encrypt
		byte [] cBytes = encrypt((DGKPublicKey) keyDGK, m).toByteArray();
		System.arraycopy(cBytes, 0, output, ciphertextSize - cBytes.length, cBytes.length);
		return ciphertextSize;
	}

	/**
	 * Perform actual decryption ,creates single array for the output and updates
	 * the result after the decryption.
	 * 
	 * @param input
	 *            - the input in bytes
	 * @param inputOffset
	 *            - the offset in input where the input starts always zero
	 * @param inputLenth
	 *            - the input length
	 * @param output
	 *            - the buffer for the result
	 * @param outputOffset
	 *            - the offset in output where the result is stored
	 * @return the number of bytes stored in output
	 */
	protected final int decrypt(byte[] input, int inputOffset, int inputLenth,
			byte[] output, int outputOffset)
	{
		// extract c
		byte[] cBytes = new byte[input.length];
		System.arraycopy(input, inputOffset, cBytes, 0, input.length);
		
		// calculate the message
		byte[] messageBytes = decrypt(new BigInteger(cBytes), (DGKPrivateKey) keyDGK).toByteArray();
		int gatedLength = Math.min(messageBytes.length, plaintextSize);
		System.arraycopy(messageBytes, 0, output, plaintextSize - gatedLength, gatedLength);
		return plaintextSize;
	}

	/**
	 * PaillierHomomorphicCipher doesn't recognise any algorithm - specific initialisations
	 * so the algorithm specific engineInit() just calls the previous overloaded
	 * version of engineInit()
	 * 
	 * @param opmode
	 *            -cipher mode
	 * @param key
	 *            - Key
	 * @param params
	 *            - AlgorithmParameterSpec
	 * @see javax.crypto.CipherSpi#engineInit(int, java.security.Key,
	 *      java.security.spec.AlgorithmParameterSpec,
	 *      java.security.SecureRandom)
	 */

	protected final void engineInit(int opmode, Key key,
			AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException
	{
		engineInit(opmode, key, random);
	}

	protected final void engineInit(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		engineInit(opmode, key, random);
	}

	/**
	 * Calls the second overloaded version of the same method.
	 * 
	 * @return the result from encryption or decryption
	 */
	protected final byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) 
	{
		byte[] out = new byte[engineGetOutputSize(inputLen)];
		try 
		{
			 engineUpdate(input, inputOffset, inputLen, out, 0);
		} 
		catch (ShortBufferException sbe) 
		{

		}
		return out;
	}

	/**
	 * Creates a single input array from the buffered data and supplied input
	 * data. Calculates the location and the length of the last fractional block
	 * in the input data. Transforms all full blocks in the input data. Save the
	 * last fractional block in the internal buffer.
	 * 
	 * @param input
	 *            - the input in bytes
	 * @param inputOffset
	 *            - the offset in input where the input starts always zero
	 * @param inputLen
	 *            - the input length
	 * @param output
	 *            - the buffer for the result
	 * @param outputOffset
	 *            - the offset in output where the result is stored
	 * @return the number of bytes stored in output
	 */
	protected final int engineUpdate(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException 
	{
		if (stateMode == Cipher.ENCRYPT_MODE)
		{
			try 
			{
				return encrypt(input, inputOffset, inputLen, output, outputOffset);
			} 
			catch (Exception e) 
			{
				e.printStackTrace();
			}
		}
		else if (stateMode == Cipher.DECRYPT_MODE)
		{
			return decrypt(input, inputOffset, inputLen, output, outputOffset);
		}
		return 0;
	}

	/**
	 * Calls the second overloaded version of the same method,
	 * to perform the required operation based on the state of the cipher.
	 * 
	 * @return returns the result from encryption or decryption
	 */
	protected final byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException
	{

		byte [] out = new byte[engineGetOutputSize(inputLen)];
		try 
		{
			engineDoFinal(input, inputOffset, inputLen, out, 0);
		} 
		catch (ShortBufferException sbe)
		{
			
		}
		return out;
	}

	/**
	 * Calls encrypt or decrypt based on the state of the cipher. Creates a
	 * single input array from the supplied input data. And returns number of
	 * bytes stored in output.
	 * 
	 * @param input
	 *            - the input buffer
	 * @param inputOffset
	 *            - the offset in input where the input starts always zero
	 * @param inputLen
	 *            - the input length
	 * @param output
	 *            - the buffer for the result
	 * @param outputOffset
	 *            - the offset in output where the result is stored
	 * @return the number of bytes stored in output
	 */
	protected final int engineDoFinal(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset)
					throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
	{
		// Create a single array of input data
		byte[] totalInput = new byte[inputLen];
		if (inputLen > 0)
		{
			System.arraycopy(input, inputOffset, totalInput, 0, inputLen);
		}
		if (stateMode == Cipher.ENCRYPT_MODE)
		{
			try 
			{
				return encrypt(input, inputOffset, inputLen, output, outputOffset);	
			} 
			catch (Exception e) 
			{
				e.printStackTrace();
			}
		}
		else if (stateMode == Cipher.DECRYPT_MODE)
		{
			return decrypt(input, inputOffset, inputLen, output, outputOffset);
		}
		return 0;
	}

	/**
	 * This method returns the appropriate block size , based on cipher.
	 * 
	 * @return BlockSize - the block size(in bytes).
	 */
	protected final int engineGetBlockSize() 
	{
		if (stateMode == Cipher.DECRYPT_MODE)
		{
			return ciphertextSize ;
		}
		else
		{
			return plaintextSize ;
		}
	}

	/**
	 * This method returns null.
	 */
	protected final byte[] engineGetIV()
	{
		return null;
	}

	/**
	 * Return  the size based on the state of the cipher. This is one 
	 * shot encryption or decryption, no need to calculate internal buffer.
	 * @param inputLen
	 *            the input length (in bytes)
	 * @return outLength - the required output size (in bytes)
	 */
	protected final int engineGetOutputSize(int inputLen)
	{
		if (stateMode == Cipher.ENCRYPT_MODE) 
		{
			return  ciphertextSize;
		} 
		else 
		{
			return plaintextSize;
		}

	}

	protected final AlgorithmParameters engineGetParameters() 
	{
		return null;
	}

	/**
	 * Initialises this cipher with key and a source of randomness
	 */
	protected final void engineInit(int mode, Key key, SecureRandom random)
			throws InvalidKeyException 
	{
		if (mode == Cipher.ENCRYPT_MODE)
		{
			if (!(key instanceof PaillierPublicKey))
			{
				throw new InvalidKeyException("I didn't get a DGKPublicKey!");
			}
		}
		else if (mode == Cipher.DECRYPT_MODE)
		{
			if (!(key instanceof PaillierPrivateKey))
			{
				throw new InvalidKeyException("I didn't get a DGKPrivateKey!");
			}
		}		
		else
		{
			throw new IllegalArgumentException("Bad mode: " + mode);
		}
		this.stateMode = mode;
		this.keyDGK = key;
		this.SECURE_RANDOM = random;
		int modulusLength = ((PaillierKey) key).getN().bitLength();
		calculateBlockSizes(modulusLength);
	}

	/**
	 * Calculates the size of the plaintext block and a ciphertext block, based
	 * on the size of the key used to initialise the cipher. The ciphertext is
	 * twice the length of the n modulus , and plaintext should be slightly
	 * shorter than the modulus. Ciphertext is little more than twice the length
	 * of the plaintext. Plaintext - we adding 8 bits(1 byte) before to divide by 8 to
	 * ensure the bigger possible plaintex will fit into created array.
	 * EngineUpdate and engineDoFinal methods check if the size of the array is
	 * to big and reduced to the right size. Similar for the ciphertext. Where
	 * the initial size is set to the size of the n^2 plus one byte . 
	 * 
	 * @param modulusLength
	 *            - n = p*q
	 */
	protected final void calculateBlockSizes(int modulusLength)
	{
		plaintextSize = ((modulusLength + 8) / 8);
		ciphertextSize = (((modulusLength + 12) / 8) * 2)-1;
	}
	
	//--------------------------------Old DGK Operations----------------------------------
	public static BigInteger encrypt(DGKPublicKey pubKey, BigInteger plaintext)
	{
		return encrypt(pubKey, plaintext.longValue());
	}

	public static BigInteger encrypt(long plaintext, DGKPublicKey pubKey)
	{
		return encrypt(pubKey, plaintext);
	}

	public static BigInteger encrypt(DGKPublicKey pubKey, long plaintext)
	{
		BigInteger ciphertext;
		//System.err.println("Exception not thrown this time...I hope you are using Protocol 1/Modified Protocol 3");
		if (plaintext < -1)
		{
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu (plaintext < 0)"
					+ " value of Plain Text is: " + plaintext);
		}
		else if (plaintext >= pubKey.u)
		{
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu"
					+ " (plaintext >= U) value of Plain Text is: " + plaintext);
		}

		// If it is null, just fill the HashMap to avoid Null Pointer!
		if (pubKey.gLUT.get(plaintext) == null)
		{
			//first part = g^m (mod n)
			pubKey.gLUT.put(plaintext, pubKey.g.modPow(BigInteger.valueOf(plaintext), pubKey.n));
		}

		// Generate 2 * t bit random number
		BigInteger r = NTL.generateXBitRandom(2 * pubKey.t);

		// First part = g^m
		BigInteger firstpart = pubKey.gLUT.get(plaintext);
		BigInteger secondpart = pubKey.h.modPow(r, pubKey.n);
		
		/*
		BigInteger secondpart = BigInteger.ONE;
		for(long i = 0; i < r.bitLength(); ++i)
		{
			//second part = h^r
			if(NTL.bit(r, i) == 1)
			{
				if(pubKey.hLUT.get(i) == null)
				{
					// e = 2^i (mod n)
					// f(i) = h^{2^i}(mod n)	
					BigInteger e = TWO.pow((int) i).mod(pubKey.n);
					pubKey.hLUT.put(i, pubKey.h.modPow(e, pubKey.n));
				}
				secondpart = secondpart.multiply(pubKey.hLUT.get(i));
			}
		}
		*/
		ciphertext = NTL.POSMOD(firstpart.multiply(secondpart), pubKey.n);
		return ciphertext;
	}

	public static BigInteger decrypt(BigInteger ciphertext, DGKPrivateKey privKey)
	{
		return BigInteger.valueOf(decrypt(privKey, ciphertext));
	}

	public static long decrypt(DGKPrivateKey privKey, BigInteger ciphertext)
	{
		if (ciphertext.signum() == -1)
		{
			throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn, "
					+ "value of cipher text is: (c < 0): " + ciphertext);
		}
		if(ciphertext.compareTo(privKey.n) == 1)
		{
			throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn,"
					+ " value of cipher text is: (c > n): " + ciphertext);
		}

		// You technically can use c^v (mod n), but you need to use a different LUT it seems...
		BigInteger decipher = NTL.POSMOD(ciphertext.modPow(privKey.vp, privKey.p), privKey.p);
		
		/*
		c = g^m * h^r (mod n)
		c^vp (mod p) = g^{vp*m} (mod p)
		Because h^{vp} (mod p) = 1
		 */
		Long plain = privKey.LUT.get(decipher);
		if(plain == null)
		{
			throw new IllegalArgumentException("Issue: DGK Public/Private Key mismatch! OR Using non-DGK encrpyted value!");
		}
		return plain;
	}

	//[a] * [b] = [a * b]
	public static BigInteger add(DGKPublicKey pubKey, BigInteger a, BigInteger b)
	{
		if (a.signum() ==-1 || a.compareTo(pubKey.n) == 1)
		{
			throw new IllegalArgumentException("DGKAdd Invalid Parameter a: at least one of the ciphertext is not in Zn: " + a);
		}
		else if (b.signum() ==-1 || b.compareTo(pubKey.n) == 1)
		{
			throw new IllegalArgumentException("DGKAdd Invalid Parameter b: at least one of the ciphertext is not in Zn: " + b);
		}
		return a.multiply(b).mod(pubKey.n);
	}
	
	//[a] * [b] = [a * b]
	public static BigInteger add_plaintext(DGKPublicKey pubKey, BigInteger a, BigInteger plaintext)
	{
		if (a.signum() ==-1 || a.compareTo(pubKey.n) == 1)
		{
			throw new IllegalArgumentException("DGKAdd Invalid Parameter a: at least one of the ciphertext is not in Zn: " + a);
		}
		// will accept plaintext -1 because of Protocol 1 and Modified Protocol 3
		else if (plaintext.compareTo(new BigInteger("-1")) == -1 || plaintext.compareTo(pubKey.bigU) == 1)
		{
			throw new IllegalArgumentException("DGKAdd Invalid Parameter b: at least one of the ciphertext is not in Zn: " + plaintext);		
		}
		return a.multiply(pubKey.g.modPow(plaintext, pubKey.n)).mod(pubKey.n);
	}
	
	public static BigInteger add_plaintext(DGKPublicKey pubKey, BigInteger a, long plaintext)
	{
		return add_plaintext(pubKey, a, BigInteger.valueOf(plaintext));
	}

	// [a]/[b] = [a - b]
	public static BigInteger subtract(DGKPublicKey pubKey, BigInteger a, BigInteger b)
	{
		BigInteger minus_b = multiply(pubKey, b, pubKey.u - 1);
		return add(pubKey, a, minus_b);
	}

	// cipher a * Plain text
	public static BigInteger multiply(DGKPublicKey pubKey, BigInteger cipher, long plaintext)
	{
		return multiply(pubKey, cipher, BigInteger.valueOf(plaintext));
	}

	public static BigInteger multiply(DGKPublicKey pubKey, BigInteger cipher, BigInteger plaintext)
	{
		if (cipher.signum() == -1)
		{
			throw new IllegalArgumentException("DGKMultiply Invalid Parameter: the ciphertext is not in Zn: " + cipher);
		}
		else if(cipher.compareTo(pubKey.n) == 1)
		{
			throw new IllegalArgumentException("DGKMultiply Invalid Parameter: the ciphertext is not in Zn: " + cipher);
		}
		// For now, I will permit negative number multiplication, especially for SST REU 2017
		if(plaintext.compareTo(pubKey.bigU) == 1)
		{
			throw new IllegalArgumentException("DGKMultiply Invalid Parameter:  the plaintext is not in Zu: " + pubKey.bigU);
		}
		return cipher.modPow(plaintext, pubKey.n);
	}

	public static BigInteger divide(DGKPublicKey pubKey, BigInteger cipher, BigInteger plaintext)
	{
		if (cipher.signum() == -1)
		{
			throw new IllegalArgumentException("DGKDivide Invalid Parameter: the ciphertext is not in Zn: " + cipher);
		}
		else if(cipher.compareTo(pubKey.n) == 1)
		{
			throw new IllegalArgumentException("DGKDivide Invalid Parameter: the ciphertext is not in Zn: " + cipher);
		}
		if(plaintext.compareTo(pubKey.bigU) == 1)
		{
			throw new IllegalArgumentException("DGKDivide Invalid Parameter: the plaintext is not in Zu: " + pubKey.bigU);
		}
		//[x]^(d^{-1})
		return cipher.modPow(plaintext.modInverse(pubKey.n), pubKey.n);
	}

	public static BigInteger divide(DGKPublicKey pubKey, BigInteger cipher, long plaintext)
	{
		return divide(pubKey, cipher, BigInteger.valueOf(plaintext));
	}

	public static BigInteger sum (DGKPublicKey pubKey, BigInteger [] parts)
	{
		BigInteger sum = DGKOperations.encrypt(pubKey, 0);
		for (int i = 0; i < parts.length; i++)
		{
			sum = add(pubKey, sum, parts[i]);
		}
		return sum;
	}

	public static BigInteger sum (DGKPublicKey pubKey, BigInteger [] parts, int limit)
	{
		BigInteger sum = DGKOperations.encrypt(pubKey, 0);
		if (limit > parts.length)
		{
			return sum(pubKey, parts);
		}
		else if(limit <= 0)
		{
			return sum;
		}
		for (int i = 0; i < limit; i++)
		{
			sum = add(pubKey, sum, parts[i]);
		}
		return sum;
	}
	
	public static BigInteger sum (DGKPublicKey pubKey, ArrayList<BigInteger> parts)
	{
		BigInteger sum = DGKOperations.encrypt(pubKey, 0);
		for (int i = 0; i < parts.size(); i++)
		{
			sum = add(pubKey, sum, parts.get(i));
		}
		return sum;
	}

	public static BigInteger sum (DGKPublicKey pubKey, ArrayList<BigInteger> parts, int limit)
	{
		BigInteger sum = DGKOperations.encrypt(pubKey, 0);
		if (limit > parts.size())
		{
			return sum(pubKey, parts);
		}
		else if(limit <= 0)
		{
			return sum;
		}
		for (int i = 0; i < limit; i++)
		{
			sum = add(pubKey, sum, parts.get(i));
		}
		return sum;
	}
	
	public static BigInteger sum_product (DGKPublicKey pubKey, ArrayList<BigInteger> cipher, ArrayList<Long> plain)
	{
		if(cipher.size() != plain.size())
		{
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}
		
		BigInteger [] product_vector = new BigInteger[cipher.size()];
		for (int i = 0; i < product_vector.length; i++)
		{
			product_vector[i] = DGKOperations.multiply(pubKey, cipher.get(i), plain.get(i));
		}
		return sum(pubKey, product_vector);
	}
	
	public static BigInteger sum_product (DGKPublicKey pubKey, BigInteger[] cipher, Long [] plain)
	{
		if(cipher.length != plain.length)
		{
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}
		
		BigInteger [] product_vector = new BigInteger[cipher.length];
		for (int i = 0; i < product_vector.length; i++)
		{
			product_vector[i] = DGKOperations.multiply(pubKey, cipher[i], plain[i]);
		}
		return sum(pubKey, product_vector);
	}
	
	// PUBLIC FACING METHODS
	public void init(int encryptMode, PaillierPublicKey pk) 
			throws InvalidKeyException, InvalidAlgorithmParameterException
	{
		engineInit(encryptMode, pk, new SecureRandom());
	}

	public void init(int decryptMode, PaillierPrivateKey sk)
			throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		engineInit(decryptMode, sk, new SecureRandom());
	}
	
	public byte[] doFinal(byte[] bytes) 
			throws BadPaddingException, IllegalBlockSizeException 
	{
		return engineDoFinal(bytes, 0, bytes.length);	
	}
}//END OF CLASS