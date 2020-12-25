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
import security.misc.CipherConstants;
import security.misc.HomomorphicException;
import security.misc.NTL;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import java.util.List;

public final class DGKOperations extends CipherSpi implements CipherConstants
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
		throw new NoSuchAlgorithmException("DGK supports no modes.");
	}

	/**
	 * This class support no padding, so engineSetPadding() throw exception when
	 * called.
	 */
	protected final void engineSetPadding(String padding)
			throws NoSuchPaddingException 
	{
		throw new NoSuchPaddingException("DGK supports no padding.");
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
		byte [] cBytes = encrypt(m, (DGKPublicKey) keyDGK).toByteArray();
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
		long dec = decrypt(new BigInteger(cBytes), (DGKPrivateKey) keyDGK);
		byte [] messageBytes = BigInteger.valueOf(dec).toByteArray();
		int gatedLength = Math.min(messageBytes.length, plaintextSize);
		System.arraycopy(messageBytes, 0, output, plaintextSize - gatedLength, gatedLength);
		return plaintextSize;
	}

	/**
	 * GM HomomorphicCipher doesn't recognise any algorithm - specific initialisations
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
			if (!(key instanceof DGKPublicKey))
			{
				throw new InvalidKeyException("I didn't get a DGKPublicKey!");
			}
		}
		else if (mode == Cipher.DECRYPT_MODE)
		{
			if (!(key instanceof DGKPrivateKey))
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
		int modulusLength = ((DGK_Key) key).getN().bitLength();
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
	
	// --------------------PUBLIC FACING METHODS--------------------------
	public void init(int encryptMode, DGKPublicKey pk) 
			throws InvalidKeyException, InvalidAlgorithmParameterException
	{
		engineInit(encryptMode, pk, new SecureRandom());
	}

	public void init(int decryptMode, DGKPrivateKey sk)
			throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		engineInit(decryptMode, sk, new SecureRandom());
	}
	
	public byte[] doFinal(byte[] bytes) 
			throws BadPaddingException, IllegalBlockSizeException 
	{
		return engineDoFinal(bytes, 0, bytes.length);	
	}
	
	//--------------------------------Old DGK Operations----------------------------------

	/**
	 * Encrypt plaintext with DGK Public Key
	 * Compute ciphertext = g^{m}h^{r} (mod n)
	 * @param pubKey - use this to encrypt plaintext
	 * @param plaintext 
	 * @return - DGK ciphertext
	 * throws HomomorphicException
	 * - If the plaintext is larger than the plaintext supported by DGK Public Key,
	 * an exception will be thrown
	 */
	public static BigInteger encrypt(long plaintext, DGKPublicKey pubKey)
	{
		BigInteger ciphertext;
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
		ciphertext = NTL.POSMOD(firstpart.multiply(secondpart), pubKey.n);
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
	 * @param privKey - used to decrypt ciphertext
	 * @param ciphertext - DGK ciphertext
	 * @return plaintext
	 * @throws HomomorphicException
	 * 	- If the ciphertext is larger than N, an exception will be thrown
	 */
	public static long decrypt(BigInteger ciphertext, DGKPrivateKey privKey)
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
		
		BigInteger decipher = NTL.POSMOD(ciphertext.modPow(privKey.vp, privKey.p), privKey.p);
		Long plain = privKey.LUT.get(decipher);
		if(plain == null)
		{
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
	 * @return
	 * @throws HomomorphicException
	 * 	- If either ciphertext is greater than N or negative, throw an exception
	 */
	public static BigInteger add(BigInteger ciphertext1, BigInteger ciphertext2, DGKPublicKey pk) 
			throws HomomorphicException
	{
		if (ciphertext1.signum() ==-1 || ciphertext1.compareTo(pk.n) == 1)
		{
			throw new HomomorphicException("DGKAdd Invalid Parameter ciphertext1: " + ciphertext1);
		}
		else if (ciphertext2.signum() ==-1 || ciphertext2.compareTo(pk.n) == 1)
		{
			throw new HomomorphicException("DGKAdd Invalid Parameter ciphertext2: " + ciphertext2);
		}
		return ciphertext1.multiply(ciphertext2).mod(pk.n);
	}
	
	
	/**
	 * returns the sum of the DGK encrypted value and plaintext value
	 * Warning: If the sum exceeds u, it is subject to mod u
	 * @param ciphertext - DGK encrypted value
	 * @param plaintext
	 * @param pk - was used to encrypt ciphertext
	 * @return Encrypted sum of ciphertext and plaintext
	 * @throws HomomorphicException 
	 * - If a ciphertext is negative or exceeds N or plaintext is negative or exceeds u
	 */
	public static BigInteger add_plaintext(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey pk) 
			throws HomomorphicException
	{
		if (ciphertext.signum() ==-1 || ciphertext.compareTo(pk.n) == 1)
		{
			throw new HomomorphicException("DGK add_plaintext Invalid Parameter ciphertext: " + ciphertext);
		}
		// will accept plaintext -1 because of Protocol 1 and Modified Protocol 3 need it
		else if (plaintext.compareTo(NEG_ONE) == -1 || plaintext.compareTo(pk.bigU) == 1)
		{
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
	 * @param ciphertext1 - DGK ciphertext
	 * @param ciphertext2 - DGK ciphertext
	 * @param pk - used to encrypt both ciphertexts
	 * @return DGK encrypted ciphertext with ciphertext1 - ciphertext2
	 * @throws HomomorphicException 
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
	 * @param plaintext 
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
	 * @param scalar - plaintext value
	 * @param pk - DGK Public key the encrypted ciphertext
	 * @return
	 * @throws HomomorphicException 
	 * If ciphertext is negative or exceeds N or plaintext exceeds u
	 */
	
	public static BigInteger multiply(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey pk) throws HomomorphicException
	{
		if (ciphertext.signum() == -1 || ciphertext.compareTo(pk.n) == 1)
		{
			throw new HomomorphicException("DGKMultiply Invalid Parameter ciphertext: " + ciphertext);
		}
		if(plaintext.compareTo(pk.bigU) == 1)
		{
			throw new HomomorphicException("DGKMultiply Invalid Parameter plaintext: " + plaintext);
		}
		return ciphertext.modPow(plaintext, pk.n);
	}
	
	public static BigInteger multiply(BigInteger cipher, long plaintext, DGKPublicKey pk) 
			throws HomomorphicException
	{
		return multiply(cipher, BigInteger.valueOf(plaintext), pk);
	}

	/**
	 * Compute the division of the DGK cipher-text and a plaintext.
	 * Warning: Divide will only work correctly on perfect divisor like 2|20, it will work.
	 * If you try 3|20, it will NOT work and you will get a wrong answer!
	 * If you want to do 3|20, you MUST use a division protocol from Veugen paper
	 * @param ciphertext - DGK ciphertext
	 * @param divisor - plaintext value
	 * @param pk - was used to encrypt ciphertext
	 * @return Encrypted DGK value equal to ciphertext/plaintext
	 * @throws HomomorphicException 
	 */
	
	public static BigInteger divide(BigInteger ciphertext, BigInteger plaintext, DGKPublicKey pk) 
			throws HomomorphicException
	{
		return multiply(ciphertext, plaintext.modInverse(pk.n), pk);
	}

	public static BigInteger divide(BigInteger ciphertext, long plaintext, DGKPublicKey pk) 
			throws HomomorphicException
	{
		return divide(ciphertext, BigInteger.valueOf(plaintext), pk);
	}

	/**
	 * Compute the sum of the encrypted DGK values
	 * @param values - Array of Encrypted DGK values 
	 * @param pk - DGKPublicKey used to encrypt all the values
	 * @return
	 * @throws HomomorphicException
	 */
	public static BigInteger sum (BigInteger [] parts, DGKPublicKey pk) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, pk);
		for (int i = 0; i < parts.length; i++)
		{
			sum = add(sum, parts[i], pk);
		}
		return sum;
	}

	/**
	 * Compute the sum of the encrypted DGK values
	 * @param values - Array of Encrypted DGK values
	 * @param pk - DGKPublicKey used to  encrypted the values
	 * @param limit - Sum values up to this index value in the list
	 * @return
	 * @throws HomomorphicException
	 */
	public static BigInteger sum (BigInteger [] values, DGKPublicKey pk, int limit) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, pk);
		if (limit > values.length)
		{
			return sum(values, pk);
		}
		else if(limit <= 0)
		{
			return sum;
		}
		for (int i = 0; i < limit; i++)
		{
			sum = add(sum, values[i], pk);
		}
		return sum;
	}
	
	/**
	 * Compute the sum of the encrypted DGK values
	 * @param values - List of Encrypted DGK values
	 * @param pk - DGKPublicKey used to  encrypted the values
	 * @param limit - Sum values up to this index value in the list
	 * @return
	 * @throws HomomorphicException
	 */
	public static BigInteger sum (List<BigInteger> values, DGKPublicKey pk) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, pk);
		for (int i = 0; i < values.size(); i++)
		{
			sum = add(sum, values.get(i), pk);
		}
		return sum;
	}
	
	/**
	 * Compute the sum of the encrypted DGK values
	 * @param values - List of Encrypted DGK values
	 * @param pk - DGKPublicKey used to  encrypted the values
	 * @param limit - Sum values up to this index value in the list
	 * @return
	 * @throws HomomorphicException
	 */
	public static BigInteger sum (List<BigInteger> values, DGKPublicKey pk, int limit) 
			throws HomomorphicException
	{
		BigInteger sum = DGKOperations.encrypt(0, pk);
		if (limit > values.size())
		{
			return sum(values, pk);
		}
		else if(limit <= 0)
		{
			return sum;
		}
		for (int i = 0; i < limit; i++)
		{
			sum = add(sum, values.get(i), pk);
		}
		return sum;
	}
	
	/**
	 * Compute the sum-product. It computes the scalar multiplication between
	 * the array of Encrypted and plaintext values.
	 * Then it computes the encrypted sum.
	 * @param cipher - List of ciphertext
	 * @param plain - List of plaintext
	 * @param pk - DGK Public Key used to encrypt list of ciphertext
	 * @return DGK Encrypted sum product
	 * @throws HomomorphicException
	 */
	public static BigInteger sum_product (List<BigInteger> ciphertext, List<Long> plaintext, DGKPublicKey pk) 
			throws HomomorphicException
	{
		if(ciphertext.size() != plaintext.size())
		{
			throw new HomomorphicException("Lists are NOT the same size!");
		}
		BigInteger sum = DGKOperations.encrypt(0, pk);
		BigInteger temp = null;
		for (int i = 0; i < ciphertext.size(); i++)
		{
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
	 * @param cipher - Array of Encrypted DGK values
	 * @param plain - Array of plaintext values
	 * @return DGK Encrypted sum-product
	 * @throws HomomorphicException
	 * - If the size of plaintext array and ciphertext array isn't equal
	 */
	
	public static BigInteger sum_product (BigInteger[] ciphertext, Long [] plaintext, DGKPublicKey pk)
			throws HomomorphicException
	{
		if(ciphertext.length != plaintext.length)
		{
			throw new HomomorphicException("Arrays are NOT the same size!");
		}
		
		BigInteger sum = DGKOperations.encrypt(0, pk);
		BigInteger temp = null;
		for (int i = 0; i < ciphertext.length; i++)
		{
			temp = DGKOperations.multiply(ciphertext[i], plaintext[i], pk);
			sum = DGKOperations.add(temp, sum, pk);
		}
		return sum;
	}
}