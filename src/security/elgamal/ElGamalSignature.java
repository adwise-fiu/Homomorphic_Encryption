package security.elgamal;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.generic.NTL;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

public class ElGamalSignature extends SignatureSpi
{
	private ElGamalPrivateKey sk;
	private ElGamalPublicKey pk;
	private boolean VERIFY_MODE;
	private byte [] encoded_hash;
	
	protected void engineInitVerify(PublicKey publicKey) 
			throws InvalidKeyException 
	{
		if(!(publicKey instanceof ElGamalPublicKey))
		{
			throw new InvalidKeyException("Didn't receive DGK Public Key!");
		}
		pk = (ElGamalPublicKey) publicKey;
		sk = null;
		VERIFY_MODE = true;
	}

	protected void engineInitSign(PrivateKey privateKey) 
			throws InvalidKeyException 
	{
		if(!(privateKey instanceof ElGamalPrivateKey))
		{
			throw new InvalidKeyException("Didn't receive ElGamal Private Key!");
		}
		pk = null;
		sk = (ElGamalPrivateKey) privateKey;
		VERIFY_MODE = false;
	}

	// Input 1:
	protected void engineUpdate(byte b) 
			throws SignatureException 
	{
		// Since I am using SHA-256, that is 256 bits or 32 bytes long!
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
		return null;
	}

	protected boolean engineVerify(byte[] sigBytes) 
			throws SignatureException 
	{
		return false;
	}

	protected void engineSetParameter(String param, Object value) 
			throws InvalidParameterException 
	{

	}

	protected Object engineGetParameter(String param) 
			throws InvalidParameterException
	{
		return null;
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
