package security.gm;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import security.misc.CipherConstants;
import security.misc.HomomorphicException;
import security.misc.NTL;

public class GMCipher extends CipherSpi implements CipherConstants
{
	protected int stateMode;
	protected Key keyGM;
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
		throw new NoSuchAlgorithmException("Goldwasser-Micali supports no modes.");
	}

	/**
	 * This class support no padding, so engineSetPadding() throw exception when
	 * called.
	 */
	protected final void engineSetPadding(String padding)
			throws NoSuchPaddingException 
	{
		throw new NoSuchPaddingException("Goldwasser-Micali supports no padding.");
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
		List<BigInteger> c = encrypt(m, (GMPublicKey) keyGM);
		for (int i = c.size() - 1; i != -1; i--)
		{
			byte [] c_i = c.get(i).toByteArray();
			System.arraycopy(c_i, 0, output, output.length - (plaintextSize * i) - c_i.length, c_i.length);
		}
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
		
		// Get list of BigIntegers from bytes
		List<BigInteger> c = new ArrayList<BigInteger>();
		int num_bits = input.length/plaintextSize;
		for(int i = num_bits - 1; i != -1;i--)
		{
			byte [] c_i = new byte[plaintextSize];
			System.arraycopy(cBytes, i * ciphertextSize, c_i, 0, c_i.length);
			BigInteger b = new BigInteger(c_i);
			c.add(b);
		}
		byte [] messageBytes = decrypt(c, (GMPrivateKey) keyGM).toByteArray();
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
		int num_bits = new BigInteger(input).bitLength();
		byte [] out = new byte[engineGetOutputSize(num_bits)];
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
		int num_bits = new BigInteger(input).bitLength();
		byte [] out = new byte[engineGetOutputSize(num_bits)];
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
			return ciphertextSize;
		}
		else
		{
			return plaintextSize;
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
	protected final int engineGetOutputSize(int num_bits)
	{
		if (stateMode == Cipher.ENCRYPT_MODE) 
		{
			return plaintextSize * num_bits;
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
			if (!(key instanceof GMPublicKey))
			{
				throw new InvalidKeyException("I didn't get a GMPublicKey!");
			}
		}
		else if (mode == Cipher.DECRYPT_MODE)
		{
			if (!(key instanceof GMPrivateKey))
			{
				throw new InvalidKeyException("I didn't get a GMPrivateKey!");
			}
		}		
		else
		{
			throw new IllegalArgumentException("Bad mode: " + mode);
		}
		this.stateMode = mode;
		this.keyGM = key;
		this.SECURE_RANDOM = random;
		int modulusLength = ((GMKey) key).getN().bitLength();
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
		plaintextSize = ((modulusLength + 8) / 8); // is N big
		ciphertextSize = ((modulusLength + 8) / 8);// is N * number of bits in N, leave equal for now
	}
	
	// -------------------------PUBLIC FACING METHODS---------------------------------
	public void init(int encryptMode, GMPublicKey pk) 
			throws InvalidKeyException, InvalidAlgorithmParameterException
	{
		engineInit(encryptMode, pk, new SecureRandom());
	}

	public void init(int decryptMode, GMPrivateKey sk)
			throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		engineInit(decryptMode, sk, new SecureRandom());
	}
		
	public byte[] doFinal(byte[] bytes) 
			throws BadPaddingException, IllegalBlockSizeException 
	{
		return engineDoFinal(bytes, 0, bytes.length);	
	}
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
		BigInteger x = null;
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
	 * @return
	 */
	public static BigInteger decrypt(List<BigInteger> cipher, GMPrivateKey sk)
	{
		BigInteger e = BigInteger.ZERO;
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
	 * @return
	 */
	public static BigInteger decrypt(BigInteger [] cipher, GMPrivateKey sk)
	{
		BigInteger e = BigInteger.ZERO;
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
	 * @throws IllegalArgumentException
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
