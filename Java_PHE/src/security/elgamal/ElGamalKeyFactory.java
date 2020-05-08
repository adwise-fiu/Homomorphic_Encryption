package security.elgamal;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ElGamalKeyFactory extends KeyFactorySpi 
{
	protected PublicKey engineGeneratePublic(KeySpec keySpec) 
			throws InvalidKeySpecException
	{
		try
		{
			if (keySpec instanceof X509EncodedKeySpec)
			{
				//X509EncodedKeySpec x509Spec = (X509EncodedKeySpec) keySpec;
				//return new DGKPublicKey(x509Spec.getEncoded());
				return null;
			}
			else
			{
				throw new InvalidKeySpecException("Only DGKPublicKeySpec "
						+ "and X509EncodedKeySpec supported for DGK public keys");
			}
		}
		catch (GeneralSecurityException e) 
		{
			throw new InvalidKeySpecException(e);
		}
	}

	protected PrivateKey engineGeneratePrivate(KeySpec keySpec) 
			throws InvalidKeySpecException 
	{
		try 
		{
			if (keySpec instanceof PKCS8EncodedKeySpec) 
			{
				return null;
				//PKCS8EncodedKeySpec pkcsSpec = (PKCS8EncodedKeySpec) keySpec;
				//return new DGKPrivateKey(pkcsSpec.getEncoded());
			}
			else 
			{
				throw new InvalidKeySpecException("Only DGKPrivateKeySpec "
						+ "and PKCS8EncodedKeySpec supported for DGK private keys");
			}
		}
		catch (GeneralSecurityException e) 
		{
			throw new InvalidKeySpecException(e);
		}
	}

	protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) 
			throws InvalidKeySpecException 
	{

		return null;
	}

	protected Key engineTranslateKey(Key key) throws InvalidKeyException 
	{
		if (key == null) 
		{
			throw new InvalidKeyException("Key must not be null");
		}
		String keyAlg = key.getAlgorithm();
		if (keyAlg.equals("DGK") == false) 
		{
			throw new InvalidKeyException("Not a DGK key: " + keyAlg);
		}
		if (key instanceof PublicKey) 
		{
			return translatePublicKey((PublicKey) key);
		}
		else if (key instanceof PrivateKey) 
		{
			return translatePrivateKey((PrivateKey) key);
		} 
		else 
		{
			throw new InvalidKeyException("Neither a public nor a private key");
		}
	}

	// internal implementation of translateKey() for public keys. See JCA doc
	private PublicKey translatePublicKey(PublicKey key)
			throws InvalidKeyException 
	{
		if (key instanceof ElGamalPublicKey) 
		{
			return key;
		} 
		else if ("X.509".equals(key.getFormat())) 
		{
			return null;
			/*
			byte[] encoded = key.getEncoded();
			return new DGKPublicKey(encoded);
			 */
		} 
		else 
		{
			throw new InvalidKeyException("Public keys must be instance "
					+ "of DGKPublicKey or have X.509 encoding");
		}
	}

	// internal implementation of translateKey() for private keys. See JCA doc
	private PrivateKey translatePrivateKey(PrivateKey key)
			throws InvalidKeyException 
	{
		if (key instanceof ElGamalPrivateKey) 
		{
			return key;
		}
		else if ("PKCS#8".equals(key.getFormat())) 
		{
			return null;
			//return new DGKPrivateKey(key.getEncoded());
		}
		else
		{
			throw new InvalidKeyException("Private keys must be instance "
					+ "of DGKPrivateKey or have PKCS#8 encoding");
		}
	}


	/**
	 * Static method to convert Key into an instance of RSAPublicKeyImpl
	 * or RSAPrivate(Crt)KeyImpl. If the key is not an RSA key or cannot be
	 * used, throw an InvalidKeyException.
	 *
	 * Used by RSASignature and RSACipher.
	 */
	public static ElGamal_Key toElGamalKey(Key key) throws InvalidKeyException 
	{
		if (key instanceof ElGamalPublicKey || key instanceof ElGamalPrivateKey)
		{
			return (ElGamal_Key) key;
		}
		else 
		{
			throw new InvalidKeyException("Not a DGK Key!");
		}
	}
}
