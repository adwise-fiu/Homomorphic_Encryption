package security.DGK;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

public class DGKSignature extends SignatureSpi
{
	
	protected void engineInitVerify(PublicKey publicKey) 
			throws InvalidKeyException 
	{

	}

	protected void engineInitSign(PrivateKey privateKey) 
			throws InvalidKeyException 
	{
		
	}

	protected void engineUpdate(byte b) 
			throws SignatureException 
	{
		
	}

	protected void engineUpdate(byte[] b, int off, int len) 
			throws SignatureException 
	{
		
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
}
