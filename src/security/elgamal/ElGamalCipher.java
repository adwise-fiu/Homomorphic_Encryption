package security.elgamal;

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

import security.generic.ConstructKey;
import security.generic.NTL;
import security.generic.PHE_Core;
import security.generic.RSAPadding;

// Reference
// https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/ElGamal.py
public class ElGamalCipher extends CipherSpi
{
	private static final boolean ADDITIVE = true;

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
	private ElGamalPublicKey publicKey;

	// the private key, if we were initialized using a private key
	private ElGamalPrivateKey privateKey;

	// hash algorithm for OAEP
	private String oaepHashAlgorithm = "SHA-1";

	public ElGamalCipher()
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
				return PHE_Core.ElGamal_encrypt(data, publicKey);
			case MODE_DECRYPT:
				byte[] decryptBuffer = PHE_Core.convert(buffer, 0, bufOfs);
				data = PHE_Core.ElGamal_decrypt(decryptBuffer, privateKey);
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
		ElGamal_Key ElKey = ElGamalKeyFactory.toElGamalKey(key);

		if (key instanceof ElGamalPublicKey) 
		{
			mode = encrypt ? MODE_ENCRYPT : MODE_VERIFY;
			publicKey = (ElGamalPublicKey) key;
			privateKey = null;
		} 
		else 
		{ 
			// must be RSAPrivateKey per check in toRSAKey
			mode = encrypt ? MODE_SIGN : MODE_DECRYPT;
			privateKey = (ElGamalPrivateKey) key;
			publicKey = null;
		}
		int n = PHE_Core.getByteLength(ElKey.getP());
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
		ElGamal_Key rsaKey = ElGamalKeyFactory.toElGamalKey(key);
		return rsaKey.getP().bitLength();
	}
	
	// --------------------------Relevant ElGamal---------------------------------------
	
	public static ElGamal_Ciphertext encrypt(ElGamalPublicKey key, BigInteger message)
	{
		if(ADDITIVE)
		{
			return Encrypt_Homomorph(key, message);
		}
		else
		{
			return Encrypt(key, message);
		}
	}
	
	public static ElGamal_Ciphertext encrypt(ElGamalPublicKey key, long m)
	{
		BigInteger message = BigInteger.valueOf(m);
		return encrypt(key, message);
	}
	
	public static BigInteger decrypt(ElGamalPrivateKey key, ElGamal_Ciphertext gr_mhr)
	{
		if(ADDITIVE)
		{
			return Decrypt_Homomorph(key, gr_mhr);	
		}
		else
		{
			return Decrypt(key, gr_mhr);	
		}
	}
	
	/*
	 * @param (p,g,h) public key
	 * @param message message	
	 */
	private static ElGamal_Ciphertext Encrypt(ElGamalPublicKey Key, BigInteger message)
	{
		BigInteger pPrime = Key.p.subtract(BigInteger.ONE).divide(ElGamalKeyPairGenerator.TWO);
		BigInteger r = NTL.RandomBnd(pPrime);
		// encrypt couple (g^r (mod p), m * h^r (mod p))
		return new ElGamal_Ciphertext(Key.g.modPow(r, Key.p), message.multiply(Key.h.modPow(r, Key.p)).mod(Key.p));
	}

	/*
	 * Encrypt ElGamal homomorphic
	 *
	 * @param (p, g, h) public key
	 * @param message message
	 */
	private static ElGamal_Ciphertext Encrypt_Homomorph(ElGamalPublicKey key, BigInteger message) 
	{
		BigInteger pPrime = key.p.subtract(BigInteger.ONE).divide(ElGamalKeyPairGenerator.TWO);
		// TODO [0, N -1] or [1, N-1] ?
		BigInteger r = NTL.RandomBnd(pPrime);
		// encrypt couple (g^r (mod p), h^r * g^m (mod p))
		BigInteger hr = key.h.modPow(r, key.p);
		BigInteger gm = key.g.modPow(message, key.p);
		return new ElGamal_Ciphertext(key.g.modPow(r, key.p), hr.multiply(gm).mod(key.p));
	}
	
	/*
	 * Decrypt ElGamal
	 *
	 * @param (p, x) secret key
	 * @param (gr, mhr) = (g^r, m * h^r)
	 * @return the decrypted message
	 */
	private static BigInteger Decrypt(ElGamalPrivateKey key, ElGamal_Ciphertext c)
	{
		BigInteger hr = c.gr.modPow(key.x, key.p);
		return c.hrgm.multiply(hr.modInverse(key.p)).mod(key.p);
	}

	/*
	 * @param (p, x) secret key
	 * @param (gr, mhr) = (g^r, h^r * g^m)
	 * @return the decrypted message
	 */
	private static BigInteger Decrypt_Homomorph(ElGamalPrivateKey key, ElGamal_Ciphertext c) 
	{
		// h^r (mod p) = g^{r * x} (mod p)
		BigInteger hr = c.gr.modPow(key.x, key.p);
		// g^m = (h^r * g^m) * (h^r)-1 (mod p) = g^m (mod p)
		BigInteger gm = c.hrgm.multiply(hr.modInverse(key.p)).mod(key.p);
		BigInteger m = key.LUT.get(gm);
		
		if (m != null)
		{
			// If I get this, there is a chance I might have a negative number to make?
			if (m.compareTo(key.FIELD_SIZE) == 1)
			{
				m = m.mod(key.p.subtract(BigInteger.ONE));
			}
			return m;
		}
		else
		{
			throw new IllegalArgumentException("Entry not found!");
		}
	}
	
	// --------------Additively Homomorphic Operations---------------------------
    // On input an encrypted value x and a scalar c, returns an encryption of cx.
    public static ElGamal_Ciphertext multiply(ElGamal_Ciphertext ciphertext1, BigInteger scalar, ElGamalPublicKey pk)
    {
    	ElGamal_Ciphertext answer = null;
    	answer = new ElGamal_Ciphertext(ciphertext1.gr.modPow(scalar, pk.p), ciphertext1.hrgm.modPow(scalar, pk.p));
        return answer;
    }
    
	public static ElGamal_Ciphertext multiply(ElGamal_Ciphertext ciphertext, long scalar, ElGamalPublicKey e_pk) 
	{
		return multiply(ciphertext, BigInteger.valueOf(scalar), e_pk);
	}
    
    // On input two encrypted values, returns an encryption of the sum of the values
    // Input is (<gr_1, mhr_1>, <gr_2, mhr_2>) --> (g^r, g^m * h^r)
    // Output is (gr_1 * gr_2, mhr_1 * mhr_2)
    public static ElGamal_Ciphertext add(ElGamal_Ciphertext ciphertext1, ElGamal_Ciphertext ciphertext2, ElGamalPublicKey pk)
    {
		ElGamal_Ciphertext answer = null;
		answer = new ElGamal_Ciphertext(ciphertext1.gr.multiply(ciphertext2.gr).mod(pk.p), 
				ciphertext1.hrgm.multiply(ciphertext2.hrgm).mod(pk.p));
		return answer;	
    }
    
    public static ElGamal_Ciphertext subtract(ElGamal_Ciphertext ciphertext1, ElGamal_Ciphertext ciphertext2, ElGamalPublicKey pk)
    {
    	ElGamal_Ciphertext neg_ciphertext2 = ElGamalCipher.multiply(ciphertext2, -1, pk);
    	ElGamal_Ciphertext ciphertext = ElGamalCipher.add(ciphertext1, neg_ciphertext2, pk);
		return ciphertext;
    }
	
	public static ElGamal_Ciphertext sum(List<ElGamal_Ciphertext> values, ElGamalPublicKey pk, int limit)
	{
		ElGamal_Ciphertext sum = ElGamalCipher.encrypt(pk, BigInteger.ZERO);
		if (limit <= 0)
		{
			return sum;
		}
		else if(limit > values.size())
		{
			for (int i = 0; i < values.size(); i++)
			{
				sum = ElGamalCipher.add(sum, values.get(i), pk);
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
		ElGamal_Ciphertext sum = ElGamalCipher.encrypt(pk, BigInteger.ZERO);
		if (limit <= 0)
		{
			return sum;
		}
		else if(limit > values.length)
		{
			for (int i = 0; i < values.length; i++)
			{
				sum = ElGamalCipher.add(sum, values[i], pk);
			}
		}
		else
		{
			for (int i = 0; i < limit; i++)
			{
				sum = ElGamalCipher.add(sum, values[i], pk);
			}
		}
		return sum;
	}
	
	public static ElGamal_Ciphertext sum_product (ElGamalPublicKey pk, List<ElGamal_Ciphertext> cipher, List<Long> plain)
	{
		if(cipher.size() != plain.size())
		{
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}
		
		ElGamal_Ciphertext [] product_vector = new ElGamal_Ciphertext[cipher.size()];
		for (int i = 0; i < product_vector.length; i++)
		{
			product_vector[i] = ElGamalCipher.multiply(cipher.get(i), plain.get(i), pk);
		}
		return ElGamalCipher.sum(product_vector, pk, product_vector.length);
	}
	
	public static ElGamal_Ciphertext sum_product (ElGamalPublicKey pk, List<ElGamal_Ciphertext> cipher, Long [] plain)
	{
		if(cipher.size() != plain.length)
		{
			throw new IllegalArgumentException("Arrays are NOT the same size!");
		}
		
		ElGamal_Ciphertext [] product_vector = new ElGamal_Ciphertext[cipher.size()];
		for (int i = 0; i < product_vector.length; i++)
		{
			product_vector[i] = ElGamalCipher.multiply(cipher.get(i), plain[i], pk);
		}
		return ElGamalCipher.sum(product_vector, pk, product_vector.length);
	}
	
	public ElGamal_Ciphertext sign(BigInteger M, ElGamalPrivateKey sk)
	{
		BigInteger p1 = sk.p.subtract(BigInteger.ONE);
		BigInteger K = null;
		while(true)
		{
			K = NTL.RandomBnd(p1);
			if(K.gcd(p1).equals(BigInteger.ONE))
			{
				break;
			}
		}

		BigInteger a = sk.g.modPow(K, sk.p);
	    BigInteger t = M.subtract(sk.x.multiply(a)).mod(p1);
	    BigInteger b = null;
	    while(t.signum() == -1)
	    {
        	t = t.add(p1);
        	b = t.multiply(K.modInverse(p1)).mod(p1);
	    }
	    return new ElGamal_Ciphertext(a, b);
	}
	
    public boolean verify(BigInteger M, ElGamal_Ciphertext sig, ElGamalPublicKey pk)
    {
    	BigInteger a = sig.getA();
    	BigInteger b = sig.getB();
    	
        if (a.compareTo(BigInteger.ZERO) <= 0 || a.compareTo(pk.p.subtract(BigInteger.ONE)) == 1)
        {
        	return false;
        }
        BigInteger v1 = pk.h.modPow(a, pk.p);
        v1 = (v1.multiply(a.modPow(b, pk.p))).mod(pk.p);
        BigInteger v2 = pk.g.modPow(M, pk.p);
        if (v1.compareTo(v2) == 0)
        {
        	return true;
        }
        return false;
    }
}
