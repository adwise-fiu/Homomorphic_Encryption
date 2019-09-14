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
import security.generic.ConstructKey;
import security.generic.NTL;
import security.generic.PHE_Core;
import security.generic.RSAPadding;

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

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.util.ArrayList;
import java.util.Locale;

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
	protected final static BigInteger TWO = new BigInteger("2");
	
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
	private DGKPublicKey publicKey;

	// the private key, if we were initialized using a private key
	private DGKPrivateKey privateKey;

	// hash algorithm for OAEP
	private String oaepHashAlgorithm = "SHA-1";

	public DGKOperations()
	{
		paddingType = PAD_PKCS1;
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

			/*
            DGK and Paillier can't do this...I think
            case MODE_SIGN:
                data = padding.pad(buffer, 0, bufOfs);
                return RSACore.rsa(data, privateKey);
            case MODE_VERIFY:
                byte[] verifyBuffer = RSACore.convert(buffer, 0, bufOfs);
                data = RSACore.rsa(verifyBuffer, publicKey);
                return padding.unpad(data);
			 */
			case MODE_ENCRYPT:
				data = padding.pad(buffer, 0, bufOfs);
				return PHE_Core.DGK_encrypt(data, publicKey);
			case MODE_DECRYPT:
				byte[] decryptBuffer = PHE_Core.convert(buffer, 0, bufOfs);
				data = PHE_Core.DGK_decrypt(decryptBuffer, privateKey);
				return padding.unpad(data);
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
		DGK_Key dgkKey = DGKKeyFactory.toDGKKey(key);

		if (key instanceof DGKPublicKey) 
		{
			mode = encrypt ? MODE_ENCRYPT : MODE_VERIFY;
			publicKey = (DGKPublicKey) key;
			privateKey = null;
		} 
		else 
		{ 
			// must be RSAPrivateKey per check in toRSAKey
			mode = encrypt ? MODE_SIGN : MODE_DECRYPT;
			privateKey = (DGKPrivateKey) key;
			publicKey = null;
		}
		int n = PHE_Core.getByteLength(dgkKey.getN());
		outputSize = n;
		bufOfs = 0;

		if (paddingType == PAD_NONE) 
		{
			if (params != null) 
			{
				throw new InvalidAlgorithmParameterException
				("Parameters not supported");
			}
			padding = RSAPadding.getInstance(RSAPadding.PAD_NONE, n, random);
			buffer = new byte[n];
		} 
		else if (paddingType == PAD_PKCS1) 
		{
			if (params != null) 
			{
				throw new InvalidAlgorithmParameterException
				("Parameters not supported");
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
					throw new InvalidAlgorithmParameterException
					("Wrong Parameters for OAEP Padding");
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
		DGK_Key rsaKey = DGKKeyFactory.toDGKKey(key);
		return rsaKey.getN().bitLength();
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

	public static BigInteger sign(BigInteger message, DGKPrivateKey privKey)
		throws IllegalArgumentException
	{
		// To avoid attacks, You need (message, v) = 1
		if(!message.gcd(privKey.v).equals(BigInteger.ONE))
		{
			throw new IllegalArgumentException("ARE YOU TRYING TO LEAK YOUR PRIVATE KEY?");
		}
		// g^{v}h^{m} (mod n) 
		BigInteger signature = privKey.g.modPow(privKey.v, privKey.n);
		signature = signature.multiply(privKey.h.modPow(message, privKey.n)).mod(privKey.n);
		return signature;
	}

	public static boolean verify(BigInteger message, BigInteger certificate, DGKPublicKey pubKey)
	{
		BigInteger challenge = certificate.modPow(pubKey.bigU, pubKey.n);
		// g^{v}h^{m} (mod n) --> g^{v * u} h^{m * u} (mod n) --> h^{m * u} (mod n)
		if (pubKey.h.modPow(message.multiply(pubKey.bigU), pubKey.n).compareTo(challenge) == 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}//END OF CLASS