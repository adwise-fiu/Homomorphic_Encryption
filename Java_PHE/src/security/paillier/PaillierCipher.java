package security.paillier;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import security.paillier.PaillierPublicKey;
import security.generic.NTL;
import security.paillier.PaillierPrivateKey;

public final class PaillierCipher extends CipherSpi
{
	protected int stateMode;
	protected Key keyPaillier;
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
		byte [] cBytes = encrypt(m, (PaillierPublicKey) keyPaillier).toByteArray();
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
		PaillierPrivateKey key = (PaillierPrivateKey) keyPaillier;

		// extract c
		byte[] cBytes = new byte[input.length];
		System.arraycopy(input, inputOffset, cBytes, 0, input.length);
		
		// calculate the message
		byte[] messageBytes = decrypt(new BigInteger(cBytes), key).toByteArray();
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
			return ciphertextSize;
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
				throw new InvalidKeyException("I didn't get a PaillierPublicKey!");
			}
		}
		else if (mode == Cipher.DECRYPT_MODE)
		{
			if (!(key instanceof PaillierPrivateKey))
			{
				throw new InvalidKeyException("I didn't get a PaillierPrivateKey!");
			}
		}		
		else
		{
			throw new IllegalArgumentException("Bad mode: " + mode);
		}
		this.stateMode = mode;
		this.keyPaillier = key;
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
		ciphertextSize = (((modulusLength + 12) / 8) * 2) - 1;
	}
	
	// -------------------------PUBLIC FACING METHODS---------------------------------
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

	//-----------------------BigInteger Paillier----------------------------------------------

    // Compute ciphertext = (mn+1)r^n (mod n^2) in two stages: (mn+1) and (r^n).
    public static BigInteger encrypt(BigInteger plaintext, PaillierPublicKey pk) 
    {
		if (plaintext.signum() == -1)
		{
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in Zu (plaintext < 0)"
					+ " value of Plain Text is: " + plaintext);
		}
		else if (plaintext.compareTo(pk.n) >= 0)
		{
			throw new IllegalArgumentException("Encryption Invalid Parameter: the plaintext is not in N"
					+ " (plaintext >= N) value of Plain Text is: " + plaintext);
		}
		
        //BigInteger randomness = new BigInteger(pk.keysize, rnd);
        BigInteger randomness = NTL.RandomBnd(pk.n);
        //BigInteger tmp1 = plaintext.multiply(pk.n).add(BigInteger.ONE).mod(pk.modulus);
        BigInteger tmp1 = pk.g.modPow(plaintext, pk.modulus);
        BigInteger tmp2 = randomness.modPow(pk.n, pk.modulus);
        BigInteger ciphertext = NTL.POSMOD(tmp1.multiply(tmp2), pk.modulus);
        return ciphertext;
    }
    
    public static BigInteger encrypt(long plaintext, PaillierPublicKey pk) 
    {
    	return PaillierCipher.encrypt(BigInteger.valueOf(plaintext), pk);
    }

    // Compute plaintext = L(c^(lambda) mod n^2) * mu mod n
    public static BigInteger decrypt(BigInteger ciphertext, PaillierPrivateKey sk)
    {
		if (ciphertext.signum() == -1)
		{
			throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn, "
					+ "value of cipher text is: (c < 0): " + ciphertext);
		}
		else if (ciphertext.compareTo(sk.modulus) == 1)
		{
			throw new IllegalArgumentException("decryption Invalid Parameter : the cipher text is not in Zn,"
					+ " value of cipher text is: (c > n): " + ciphertext);
		}
        //BigInteger plaintext = L(ciphertext.modPow(sk.lambda, sk.modulus), sk.n).multiply(sk.mu).mod(sk.n);
        BigInteger plaintext = L(ciphertext.modPow(sk.lambda, sk.modulus), sk.n).multiply(sk.rho).mod(sk.n);
        return plaintext;
    }

    // On input two encrypted values, returns an encryption of the sum of the
    // values
    public static BigInteger add(BigInteger ciphertext1, BigInteger ciphertext2, PaillierPublicKey pk)
    {
        BigInteger ciphertext = ciphertext1.multiply(ciphertext2).mod(pk.modulus);
        return ciphertext;
    }
    
    public static BigInteger add_plaintext(BigInteger ciphertext, BigInteger plaintext, PaillierPublicKey pk)
    {
        BigInteger new_ciphertext = ciphertext.multiply(pk.g.modPow(plaintext, pk.modulus)).mod(pk.modulus);
        return new_ciphertext;
    }
    
    public static BigInteger add_plaintext(BigInteger ciphertext, long plaintext, PaillierPublicKey pk)
    {
        BigInteger new_ciphertext = ciphertext.multiply(pk.g.modPow(BigInteger.valueOf(plaintext), pk.modulus)).mod(pk.modulus);
        return new_ciphertext;
    }
    
    public static BigInteger subtract(BigInteger ciphertext1, BigInteger ciphertext2, PaillierPublicKey pk)
    {
    	BigInteger neg_ciphertext2 = PaillierCipher.multiply(ciphertext2, pk.n.subtract(BigInteger.ONE), pk);
		BigInteger ciphertext = ciphertext1.multiply(neg_ciphertext2).mod(pk.modulus);
		return ciphertext;
    }
    
    // On input an encrypted value [[x]] and a scalar c, returns an encryption of [[cx]].
    // For now, I will permit negative number multiplication, especially for SST REU 2017
    public static BigInteger multiply(BigInteger ciphertext1, BigInteger scalar, PaillierPublicKey pk)
    {
        BigInteger ciphertext = ciphertext1.modPow(scalar, pk.modulus);
        return ciphertext;
    }

    public static BigInteger multiply(BigInteger ciphertext1, long scalar, PaillierPublicKey pk) 
    {
        return multiply(ciphertext1, BigInteger.valueOf(scalar), pk);
    }
    
    // L(u) = (u - 1)/n
    protected static BigInteger L(BigInteger u, BigInteger n) 
    {
        return u.subtract(BigInteger.ONE).divide(n);
    }
    
	public static BigInteger sum(BigInteger [] values, PaillierPublicKey pk)
	{
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		for (int i = 0; i < values.length; i++)
		{
			sum = PaillierCipher.add(sum, values[i], pk);
		}
		return sum;
	}
	
	public static BigInteger sum(BigInteger [] values, PaillierPublicKey pk, int limit)
	{
		if (limit > values.length)
		{
			return sum(values, pk);
		}
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		if (limit <= 0)
		{
			return sum;
		}
		for (int i = 0; i < limit; i++)
		{
			sum = PaillierCipher.add(sum, values[i], pk);
		}
		return sum;
	}
	
	public static BigInteger summation(ArrayList<BigInteger> values, PaillierPublicKey pk)
	{
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		for (int i = 0; i < values.size(); i++)
		{
			sum = PaillierCipher.add(sum, values.get(i), pk);
		}
		return sum;
	}
	
	public static BigInteger summation(ArrayList<BigInteger> values, PaillierPublicKey pk, int limit)
	{
		if (limit > values.size())
		{
			return summation(values, pk);
		}
		BigInteger sum = PaillierCipher.encrypt(BigInteger.ZERO, pk);
		if (limit <= 0)
		{
			return sum;
		}
		for (int i = 0; i < limit; i++)
		{
			sum = PaillierCipher.add(sum, values.get(i), pk);
		}
		return sum;
	}
	
	public static BigInteger sum_product (PaillierPublicKey pk, List<BigInteger> cipher, List<Long> plain)
	{
		if(cipher.size() != plain.size())
		{
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}
		
		BigInteger [] product_vector = new BigInteger[cipher.size()];
		for (int i = 0; i < product_vector.length; i++)
		{
			product_vector[i] = PaillierCipher.multiply(cipher.get(i), plain.get(i), pk);
		}
		return sum(product_vector, pk);
	}
	
	public static BigInteger sum_product (PaillierPublicKey pk, BigInteger[] cipher, Long[] plain)
	{
		if(cipher.length != plain.length)
		{
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}
		
		BigInteger [] product_vector = new BigInteger[cipher.length];
		for (int i = 0; i < product_vector.length; i++)
		{
			product_vector[i] = PaillierCipher.multiply(cipher[i], plain[i], pk);
		}
		return sum(product_vector, pk);
	}
	/*
	 * Please note: Divide will only work correctly on perfect divisor
	 * 2|20, it will work.
	 * if you try 3|20, it will NOT work and you will get a wrong answer!
	 * 
	 * If you want to do 3|20, you MUST use a division protocol from Veugen paper
	 */
	public static BigInteger divide(BigInteger ciphertext, long divisor, PaillierPublicKey pk)
	{
		return divide(ciphertext, BigInteger.valueOf(divisor), pk);
	}
	
	public static BigInteger divide(BigInteger ciphertext, BigInteger divisor, PaillierPublicKey pk)
	{
		return multiply(ciphertext, divisor.modInverse(pk.modulus), pk);
	}
	
}