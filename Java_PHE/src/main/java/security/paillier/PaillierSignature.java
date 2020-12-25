package security.paillier;

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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// A guide
//https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/rsa/DigestSignatureSpi.java
public class PaillierSignature extends SignatureSpi
{
	private PaillierPrivateKey sk;
	private PaillierPublicKey pk;
	private boolean VERIFY_MODE;
	private byte [] encoded_hash;
	
	// For Paillier Verify
	private List<BigInteger> sigma = null;
	
	protected void engineInitVerify(PublicKey publicKey) 
			throws InvalidKeyException 
	{
		if(!(publicKey instanceof PaillierPublicKey))
		{
			throw new InvalidKeyException("Didn't receive Paillier Public Key!");
		}
		pk = (PaillierPublicKey) publicKey;
		sk = null;
		VERIFY_MODE = true;
	}

	protected void engineInitSign(PrivateKey privateKey) 
			throws InvalidKeyException 
	{
		if(!(privateKey instanceof PaillierPrivateKey))
		{
			throw new InvalidKeyException("Didn't receive Paillier Private Key!");
		}
		pk = null;
		sk = (PaillierPrivateKey) privateKey;
		VERIFY_MODE = false;
	}

	// Input 1:
	protected void engineUpdate(byte b) 
			throws SignatureException 
	{
		// Since I am using SHA-256, that is 256 bits or 256/8 bytes long!
		MessageDigest digest = null;
		try 
		{
			digest = MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		this.encoded_hash = digest.digest(new byte [] { b });		
	}

	// Input 2: Prepare bytes to sign or verify!
	protected void engineUpdate(byte [] b, int off, int len) 
			throws SignatureException 
	{
		// Since I am using SHA-256, that is 256 bits or 256/8 bytes long!
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
		byte [] s = null;
		byte [] s_1 = null;
		byte [] s_2 = null;
		if(VERIFY_MODE)
		{
			throw new SignatureException("Did not Initialize SignInit!");
		}
		else
		{
			sigma = sign(new BigInteger(encoded_hash), sk);
			s_1 = sigma.get(0).toByteArray();
			s_2 = sigma.get(1).toByteArray();
			// Concat both BigIntegers!
			s = new byte[s_1.length + s_2.length];
			System.arraycopy(s_1, 0, s, 0, s_1.length);
			System.arraycopy(s_2, 0, s, s_1.length, s_2.length);
		}
		return s;
	}

	protected boolean engineVerify(byte[] sigBytes) 
			throws SignatureException 
	{
		if(VERIFY_MODE)
		{
			// Split sigBytes into Sigma_1 and Sigma_2!
			// sigma 1 seems to consistently be 384 bytes long
			// sigma 2 seems to be consistently 128 or 129 bytes long
			BigInteger sigma_one = new BigInteger(Arrays.copyOfRange(sigBytes, 0, 384));
			BigInteger sigma_two = new BigInteger(Arrays.copyOfRange(sigBytes, 384, sigBytes.length));
			
			// arg1 = message, arg2 & arg3 = signed hash
			return verify(new BigInteger(encoded_hash), sigma_one, sigma_two, pk);			
		}
		else
		{
			throw new SignatureException("Didn't Initialize Engine Verify Mode!");
		}
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
	public void initSign(PaillierPrivateKey sk) throws InvalidKeyException
	{
		engineInitSign(sk);
	}
	
	public void initVerify(PaillierPublicKey pk) throws InvalidKeyException
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
	 * Please refer to "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes"
	 * @param message to sign
	 * @param sk - used to sign message
	 * @return
	 */
	public static List<BigInteger> sign(BigInteger message, PaillierPrivateKey sk)
	{
		List<BigInteger> tuple = new ArrayList<BigInteger>();
		BigInteger sigma_one = PaillierCipher.L(message.modPow(sk.lambda, sk.modulus), sk.n);
		sigma_one = sigma_one.multiply(sk.rho);
		
		BigInteger sigma_two = message.multiply(sk.g.modPow(sigma_one, sk.n).modInverse(sk.n));
		sigma_two = sigma_two.modPow(sk.n.modInverse(sk.lambda), sk.n);
		
		tuple.add(sigma_one);
		tuple.add(sigma_two);
		return tuple;
	}
	
	/**
	 * Verify a Paillier signature
	 * @param message - Plaintext message to verify
	 * @param sigma_one - First component of signature
	 * @param sigma_two - Second component of signature
	 * @param pk - Used to verify signature
	 * @return - true - valid, false - invalid
	 */
	public static boolean verify(BigInteger message, BigInteger sigma_one, BigInteger sigma_two, PaillierPublicKey pk)
	{
		BigInteger first_part = pk.g.modPow(sigma_one, pk.modulus);
		BigInteger second_part = sigma_two.modPow(pk.n, pk.modulus);
		if (message.compareTo(first_part.multiply(second_part).mod(pk.modulus)) == 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}
