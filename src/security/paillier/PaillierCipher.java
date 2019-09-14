package security.paillier;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import security.paillier.PaillierPublicKey;
import security.generic.ConstructKey;
import security.generic.NTL;
import security.generic.PHE_Core;
import security.generic.RSAPadding;
import security.paillier.PaillierPrivateKey;

public final class PaillierCipher extends CipherSpi
{
    private static SecureRandom rnd = new SecureRandom();
    
	// constant for an empty byte array
	private final static byte[] B0 = new byte[0];

	// mode constant for public key encryption
	private final static int MODE_ENCRYPT = 1;

	// mode constant for private key decryption
	private final static int MODE_DECRYPT = 2;

	// mode constant for private key encryption (signing)
	private final static int MODE_SIGN    = 3;

	// mode constant for public key decryption (verifying)
	private final static int MODE_VERIFY  = 4;

	// constant for raw RSA
	private final static String PAD_NONE  = "NoPadding";

	// constant for PKCS#1 v1.5 RSA
	private final static String PAD_PKCS1 = "PKCS1Padding";

	// constant for PKCS#2 v2.0 OAEP with MGF1
	private final static String PAD_OAEP_MGF1  = "OAEP";

	// current mode, one of MODE_* above. Set when init() is called
	private int mode;

	// active padding type, one of PAD_* above. Set by setPadding()
	private String paddingType;

	// padding object
	private RSAPadding padding;

	// cipher parameter for OAEP padding
	private OAEPParameterSpec spec = null;

	// buffer for the data
	private byte[] buffer;

	// offset into the buffer (number of bytes buffered)
	private int bufOfs;

	// size of the output
	private int outputSize;

	// the public key, if we were initialized using a public key
	private PaillierPublicKey publicKey;

	// the private key, if we were initialized using a private key
	private PaillierPrivateKey privateKey;

	// hash algorithm for OAEP
	private String oaepHashAlgorithm = "SHA-1";

	public PaillierCipher()
	{
		paddingType = PAD_NONE;
	}

	// internal doFinal() method. Here we perform the actual RSA operation
	private byte[] doFinal() 
			throws BadPaddingException, IllegalBlockSizeException 
	{
		if (bufOfs > buffer.length) 
		{
			throw new IllegalBlockSizeException("Data must not be longer "
					+ "than " + buffer.length + " bytes");
		}
		try
		{
			byte[] data;
			switch (mode) 
			{
				case MODE_SIGN:
					data = padding.pad(buffer, 0, bufOfs);
					return null;
					//return PHE_Core.rsa(data, privateKey);
				case MODE_VERIFY:
					//byte[] verifyBuffer = PHE_Core.convert(buffer, 0, bufOfs);
					//data = PHE_Core.rsa(verifyBuffer, publicKey);
					//return padding.unpad(data);
					return null;
				case MODE_ENCRYPT:
					//data = buffer;
					data = padding.pad(buffer, 0, bufOfs);
					return PHE_Core.Paillier_encrypt(data, publicKey);
				case MODE_DECRYPT:
					//byte[] decryptBuffer = buffer;
					byte [] decryptBuffer = PHE_Core.convert(buffer, 0, bufOfs);
					data = PHE_Core.Paillier_decrypt(decryptBuffer, privateKey);
					//return padding.unpad(data);
					return data;
				default:
					throw new AssertionError("Internal error");
			}
		} 
		finally 
		{
			bufOfs = 0;
		}
	}

	// see JCE spec
	protected byte[] engineDoFinal(byte[] in, int inOfs, int inLen)
			throws BadPaddingException, IllegalBlockSizeException 
	{
		update(in, inOfs, inLen);
		return doFinal();
	}

	protected int engineDoFinal(byte[] in, int inOfs, int inLen, byte[] out, int outOfs)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException 
	{
		if (outputSize > out.length - outOfs) 
		{
			throw new ShortBufferException("Need " + outputSize + " bytes for output");	
		}
		update(in, inOfs, inLen);
		byte[] result = doFinal();
		int n = result.length;
		System.arraycopy(result, 0, out, outOfs, n);
		return n;
	}

	// see JCE spec
	protected byte[] engineWrap(Key key) 
			throws InvalidKeyException, IllegalBlockSizeException 
	{
		byte [] encoded = key.getEncoded();
		if ((encoded == null) || (encoded.length == 0)) 
		{
			throw new InvalidKeyException("Could not obtain encoded key");
		}
		if (encoded.length > buffer.length) 
		{
			throw new InvalidKeyException("Key is too long for wrapping");
		}
		update(encoded, 0, encoded.length);
		try 
		{
			return doFinal();
		}
		catch (BadPaddingException e) 
		{
			// should not occur
			throw new InvalidKeyException("Wrapping failed", e);
		}
	}

	// see JCE spec
	protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type) 
			throws InvalidKeyException, NoSuchAlgorithmException 
	{
		if (wrappedKey.length > buffer.length) 
		{
			throw new InvalidKeyException("Key is too long for unwrapping");
		}
		update(wrappedKey, 0, wrappedKey.length);
		try 
		{
			byte[] encoded = doFinal();
			return ConstructKey.constructKey(encoded, algorithm, type);
		}
		catch (BadPaddingException e) 
		{
			// should not occur
			throw new InvalidKeyException("Unwrapping failed", e);
		} 
		catch (IllegalBlockSizeException e) 
		{
			// should not occur, handled with length check above
			throw new InvalidKeyException("Unwrapping failed", e);
		}
	}

	// return 0 as block size, we are not a block cipher
	// see JCE spec
	protected int engineGetBlockSize() 
	{
		return 0;
	}

	// no iv, return null
	// see JCE spec
	protected byte[] engineGetIV() 
	{
		return null;
	}

	protected int engineGetOutputSize(int arg0) 
	{
		return outputSize;
	}

	protected AlgorithmParameters engineGetParameters() 
	{
		if (spec != null) 
		{
			try 
			{
				AlgorithmParameters params =
						AlgorithmParameters.getInstance("OAEP", "SunJCE");
				params.init(spec);
				return params;
			} 
			catch (NoSuchAlgorithmException nsae) 
			{
				// should never happen
				throw new RuntimeException("Cannot find OAEP " +
						" AlgorithmParameters implementation in SunJCE provider");
			} 
			catch (NoSuchProviderException nspe) 
			{
				// should never happen
				throw new RuntimeException("Cannot find SunJCE provider");
			} 
			catch (InvalidParameterSpecException ipse) 
			{
				// should never happen
				throw new RuntimeException("OAEPParameterSpec not supported");
			}
		} 
		else 
		{
			return null;
		}
	}

	// see JCE spec
	protected void engineInit(int opmode, Key key, SecureRandom random)
			throws InvalidKeyException 
	{
		try 
		{
			init(opmode, key, random, null);
		}
		catch (InvalidAlgorithmParameterException iape) 
		{
			// never thrown when null parameters are used;
			// but re-throw it just in case
			InvalidKeyException ike =
					new InvalidKeyException("Wrong parameters");
			ike.initCause(iape);
			throw ike;
		}
	}

	// see JCE spec
	protected void engineInit(int opmode, Key key,
			AlgorithmParameterSpec params, SecureRandom random)
					throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		init(opmode, key, random, params);
	}

	// see JCE spec
	protected void engineInit(int opmode, Key key,
			AlgorithmParameters params, SecureRandom random)
					throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		if (params == null)
		{
			init(opmode, key, random, null);
		}
		else 
		{
			try 
			{
				OAEPParameterSpec spec =
						params.getParameterSpec(OAEPParameterSpec.class);
				init(opmode, key, random, spec);
			} 
			catch (InvalidParameterSpecException ipse) 
			{
				InvalidAlgorithmParameterException iape =
						new InvalidAlgorithmParameterException("Wrong parameter");
				iape.initCause(ipse);
				throw iape;
			}
		}
	}

	// initialize this cipher
	private void init(int opmode, Key key, SecureRandom random, AlgorithmParameterSpec params)
			throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		boolean encrypt;
		switch (opmode) 
		{
		case Cipher.ENCRYPT_MODE:
		case Cipher.WRAP_MODE:
			encrypt = true;
			break;

		case Cipher.DECRYPT_MODE:
		case Cipher.UNWRAP_MODE:
			encrypt = false;
			break;

		default:
			throw new InvalidKeyException("Unknown mode: " + opmode);

		}
		PaillierKey paillierKey = PaillierKeyFactory.toPaillierKey(key);

		if (key instanceof PaillierPublicKey) 
		{
			mode = encrypt ? MODE_ENCRYPT : MODE_VERIFY;
			publicKey = (PaillierPublicKey) key;
			privateKey = null;
		} 
		else 
		{
			mode = encrypt ? MODE_SIGN : MODE_DECRYPT;
			privateKey = (PaillierPrivateKey) key;
			publicKey = null;
		}
		int n = PHE_Core.getByteLength(paillierKey.getModulus());
		outputSize = n;
		bufOfs = 0;

		if (paddingType == PAD_NONE) 
		{
			if (params != null) 
			{
				throw new InvalidAlgorithmParameterException("Parameters not supported");
			}
			padding = RSAPadding.getInstance(RSAPadding.PAD_NONE, n, random);
			buffer = new byte[n];
		}
		else if (paddingType == PAD_PKCS1) 
		{
			if (params != null) 
			{
				throw new InvalidAlgorithmParameterException("Parameters not supported");
			}
			int blockType = (mode <= MODE_DECRYPT) ? RSAPadding.PAD_BLOCKTYPE_2
					: RSAPadding.PAD_BLOCKTYPE_1;
			padding = RSAPadding.getInstance(blockType, n, random);

			if (encrypt) 
			{
				int k = padding.getMaxDataSize();
				buffer = new byte[k];
			} 
			else 
			{
				buffer = new byte[n];
			}
		} 
		else 
		{ 
			// PAD_OAEP_MGF1
			if ((mode == MODE_SIGN) || (mode == MODE_VERIFY)) 
			{
				throw new InvalidKeyException("OAEP cannot be used to sign or verify signatures");
			}
			OAEPParameterSpec myParams;
			if (params != null)
			{
				if (!(params instanceof OAEPParameterSpec)) 
				{
					throw new InvalidAlgorithmParameterException("Wrong Parameters for OAEP Padding");
				}
				myParams = (OAEPParameterSpec) params;
			} 
			else 
			{
				myParams = new OAEPParameterSpec(oaepHashAlgorithm, "MGF1",
						MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
			}
			padding = RSAPadding.getInstance(RSAPadding.PAD_OAEP_MGF1, n, random, myParams);
			if (encrypt) 
			{
				int k = padding.getMaxDataSize();
				buffer = new byte[k];
			} 
			else 
			{
				buffer = new byte[n];
			}
		}
	}

	protected void engineSetMode(String mode) 
			throws NoSuchAlgorithmException 
	{
		if (mode.equalsIgnoreCase("ECB") == false) 
		{
			throw new NoSuchAlgorithmException("Unsupported mode " + mode);
		}
	}

	protected void engineSetPadding(String paddingName) 
			throws NoSuchPaddingException
	{
		if (paddingName.equalsIgnoreCase(PAD_NONE))
		{
			paddingType = PAD_NONE;
		} 
		else if (paddingName.equalsIgnoreCase(PAD_PKCS1)) 
		{
			paddingType = PAD_PKCS1;
		} 
		else 
		{
			String lowerPadding = paddingName.toLowerCase(Locale.ENGLISH);
			if (lowerPadding.equals("oaeppadding")) 
			{
				paddingType = PAD_OAEP_MGF1;
			}
			else if (lowerPadding.startsWith("oaepwith") &&
					lowerPadding.endsWith("andmgf1padding")) 
			{
				paddingType = PAD_OAEP_MGF1;
				// "oaepwith".length() == 8
				// "andmgf1padding".length() == 14
				oaepHashAlgorithm = paddingName.substring(8, paddingName.length() - 14);
				// check if MessageDigest appears to be available
				// avoid getInstance() call here
			    Provider [] providerList = Security.getProviders();
			    for (Provider provider : providerList)
			    {
			    	if (provider.getService("MessageDigest", oaepHashAlgorithm) == null) 
					{
						throw new NoSuchPaddingException("MessageDigest not available for " + paddingName);
					}
				}
			}
			else 
			{
				throw new NoSuchPaddingException ("Padding " + paddingName + " not supported");
			}
		}
	}

	// see JCE spec
	protected byte[] engineUpdate(byte[] in, int inOfs, int inLen) 
	{
		update(in, inOfs, inLen);
		return B0;
	}

	// see JCE spec
	protected int engineUpdate(byte[] in, int inOfs, int inLen, byte[] out,
			int outOfs) 
	{
		update(in, inOfs, inLen);
		return 0;
	}

	// internal update method
	private void update(byte[] in, int inOfs, int inLen) 
	{
		if ((inLen == 0) || (in == null)) 
		{
			return;
		}

		if (bufOfs + inLen > buffer.length) 
		{
			bufOfs = buffer.length + 1;
			return;
		}
		System.arraycopy(in, inOfs, buffer, bufOfs, inLen);
		bufOfs += inLen;
	}

	// see JCE spec
	protected int engineGetKeySize(Key key) throws InvalidKeyException
	{
		PaillierKey paillierKey = PaillierKeyFactory.toPaillierKey(key);
		return paillierKey.getModulus().bitLength();
	}

	//-----------------------Old Paillier----------------------------------------------

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
		
        BigInteger randomness = new BigInteger(pk.keysize, rnd);
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
	
	// Return <sigma_1, sigma_2>
	public static List<BigInteger> sign(BigInteger message, PaillierPrivateKey sk)
	{
		List<BigInteger> tuple = new ArrayList<BigInteger>();
		// Hash(m) then do modPow!
		BigInteger sigma_one = L(message.modPow(sk.lambda, sk.modulus), sk.n);
		sigma_one = sigma_one.multiply(sk.rho);
		
		BigInteger sigma_two = message.multiply(sk.g.modPow(sigma_one, sk.n).modInverse(sk.n));
		sigma_two = sigma_two.modPow(sk.n.modInverse(sk.lambda), sk.n);
		
		tuple.add(sigma_one);
		tuple.add(sigma_two);
		return tuple;
	}
	
	public static boolean verify(BigInteger message, List<BigInteger> sigma, PaillierPublicKey pk)
	{
		return verify(message, sigma.get(0), sigma.get(1), pk);
	}
	
	public static boolean verify(BigInteger message, BigInteger sigma_one, BigInteger sigma_two, PaillierPublicKey pk)
	{
		BigInteger first_part = pk.g.modPow(sigma_one, pk.modulus);
		BigInteger second_part = sigma_two.modPow(pk.n, pk.modulus);
		// Compare with Hash!
		if (message.compareTo(first_part.multiply(second_part).mod(pk.modulus)) == 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	// PUBLIC FACING METHODS
	public void init(int encryptMode, PaillierPublicKey pk) 
			throws InvalidKeyException, InvalidAlgorithmParameterException
	{
		init(encryptMode, pk, rnd, null);
	}

	public byte[] engineDoFinal(byte[] bytes) 
			throws BadPaddingException, IllegalBlockSizeException 
	{
		return engineDoFinal(bytes, 0, bytes.length);	
	}

	public void init(int decryptMode, PaillierPrivateKey sk)
			throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		init(decryptMode, sk, rnd, null);
	}
	
	public String toString()
	{
		String answer = "";
		answer += "MODE: " + mode + '\n';
		answer += "PADDING TYPE: " + paddingType + '\n';
		//answer += "Padding object: " + padding.toString() + '\n';
		if(buffer != null)
		{
			answer += "buffer: " + buffer.length + '\n';
		}
		answer += "buffer offset: " +  bufOfs + '\n';
		answer += "output Size: " + outputSize + '\n';
		if(publicKey != null)
		{
			answer += "PublicKey: " + publicKey.toString() + '\n';
			answer += "PrivateKey: NULL\n";
		}
		else
		{
			answer += "PublicKey: NULL\n";
			answer += "PrivateKey: " + privateKey.toString() + '\n';
		}
		return answer;
	}
}