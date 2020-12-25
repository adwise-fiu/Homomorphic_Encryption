package security.DGK;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

public class DGKSignature extends SignatureSpi
{
	private DGKPrivateKey sk;
	private DGKPublicKey pk;
	private boolean VERIFY_MODE;
	private byte [] encoded_hash;
	
	protected void engineInitVerify(PublicKey publicKey) 
			throws InvalidKeyException 
	{
		if(!(publicKey instanceof DGKPublicKey))
		{
			throw new InvalidKeyException("Didn't receive DGK Public Key!");
		}
		pk = (DGKPublicKey) publicKey;
		sk = null;
		VERIFY_MODE = true;
	}

	protected void engineInitSign(PrivateKey privateKey) 
			throws InvalidKeyException 
	{
		if(!(privateKey instanceof DGKPrivateKey))
		{
			throw new InvalidKeyException("Didn't receive DGK Private Key!");
		}
		pk = null;
		sk = (DGKPrivateKey) privateKey;
		VERIFY_MODE = false;
	}

	// Input 1:
	protected void engineUpdate(byte b) 
			throws SignatureException 
	{
		// Since I am using SHA-256, that is 256 bits or 32 bytes long!
		MessageDigest digest = null;
		try 
		{
			digest = MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		this.encoded_hash = digest.digest(new byte [] {b});
	}

	// Input 2: Prepare bytes to sign or verify!
	protected void engineUpdate(byte [] b, int off, int len) 
			throws SignatureException 
	{
		// Since I am using SHA-256, that is 256 bits or 32 bytes long!
		MessageDigest digest = null;
		try 
		{
			digest = MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		this.encoded_hash = digest.digest(b);
	}

	protected byte[] engineSign()
			throws SignatureException 
	{
		if(VERIFY_MODE)
		{
			throw new SignatureException("Didn't Initialize Sign Mode!");
		}
		else
		{
			return sign(new BigInteger(this.encoded_hash), sk).toByteArray();	
		}
	}

	protected boolean engineVerify(byte[] sigBytes) 
			throws SignatureException 
	{
		return verify(new BigInteger(encoded_hash), new BigInteger(sigBytes), pk);
	}
	
	protected void engineSetParameter(AlgorithmParameterSpec param) 
			throws InvalidParameterException 
	{
		
	}

	protected void engineSetParameter(String param, Object value) 
			throws InvalidParameterException 
	{
		
	}
	
	protected AlgorithmParameters engineGetParameter() 
			throws InvalidParameterException
	{
		return null;
	}

	protected Object engineGetParameter(String param) 
			throws InvalidParameterException
	{
		return null;
	}
	
	// PUBLIC FACING FUNCTIONS
	public void initSign(DGKPrivateKey sk) throws InvalidKeyException
	{
		engineInitSign(sk);
	}
	
	public void initVerify(DGKPublicKey pk) throws InvalidKeyException
	{
		engineInitVerify(pk);
	}
		
	public void update(byte [] b) throws SignatureException
	{
		engineUpdate(b, 0, b.length);
	}
		
	public byte [] sign() throws SignatureException
	{
		return engineSign();
	}
		
	public boolean verify(byte [] signature) throws SignatureException
	{
		return engineVerify(signature);
	}
	
	/**
	 * Sign a message with DGK Private Key
	 * NOTE: THIS HAS NOT BEEN TESTED OR VERIFIED AS CRYTPOGRAPHICALLY SECURE
	 * @param message - plaintext to sign
	 * @param sk - used to sign the message
	 * @return signed bytes
	 * @throws IllegalArgumentException
	 */
	public static BigInteger sign(BigInteger message, DGKPrivateKey sk)
			throws IllegalArgumentException
	{
		BigInteger signature = null;
		// g^{v} * {m} (mod n) 
		signature = sk.g.modPow(sk.v, sk.n);
		signature = signature.multiply(message).mod(sk.n);
		return signature;
	}
	
	/**
	 * Verify a message with a DGK Public Key
	 * NOTE: THIS HAS NOT BEEN TESTED OR VERIFIED AS CRYTPOGRAPHICALLY SECURE
	 * @param message - plaintext
	 * @param signature - signed message to verify
	 * @param pk - Used to verify signed message integrity
	 * @return - true - is valid, false - not valid
	 */
	
	public static boolean verify(BigInteger message, BigInteger signature, DGKPublicKey pk)
	{
		BigInteger challenge = signature.modPow(pk.bigU, pk.n);
		// g^{v} * {m} (mod n) --> g^{v * u} * { m } (mod n) --> m^{u} (mod n)
		if (message.modPow(pk.bigU, pk.n).compareTo(challenge) == 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}
