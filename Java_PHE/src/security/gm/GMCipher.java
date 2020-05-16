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
import java.util.List;

import security.generic.CipherConstants;
import security.generic.NTL;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class GMCipher extends CipherSpi implements CipherConstants
{
	protected byte[] engineDoFinal(byte[] arg0, int arg1, int arg2)
			throws IllegalBlockSizeException, BadPaddingException
	{
		return null;
	}

	protected int engineDoFinal(byte[] arg0, int arg1, int arg2, byte[] arg3, int arg4)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
	{
		return 0;
	}

	
	protected int engineGetBlockSize() 
	{
		return 0;
	}
	
	protected byte[] engineGetIV() 
	{
		return null;
	}
	
	protected int engineGetOutputSize(int arg0) 
	{
		return 0;
	}
	
	protected AlgorithmParameters engineGetParameters() 
	{
		return null;
	}
	
	protected void engineInit(int arg0, Key arg1, SecureRandom arg2) throws InvalidKeyException
	{

	}
	
	protected void engineInit(int arg0, Key arg1, AlgorithmParameterSpec arg2, SecureRandom arg3)
			throws InvalidKeyException, InvalidAlgorithmParameterException 
	{
		
	}
	
	protected void engineInit(int arg0, Key arg1, AlgorithmParameters arg2, SecureRandom arg3)
			throws InvalidKeyException, InvalidAlgorithmParameterException
	{
		
	}
	
	protected void engineSetMode(String arg0) throws NoSuchAlgorithmException 
	{
		
	}
	
	protected void engineSetPadding(String arg0) throws NoSuchPaddingException
	{
		
	}
	
	protected byte[] engineUpdate(byte[] arg0, int arg1, int arg2) 
	{
		return null;
	}
	
	protected int engineUpdate(byte[] arg0, int arg1, int arg2, byte[] arg3, int arg4) throws ShortBufferException
	{
		return 0;
	}
	
	public static List<BigInteger> encrypt(BigInteger m, GMPublicKey pk)
	{
		List<BigInteger> enc_bits = new ArrayList<BigInteger>();  
	    char [] bit_array = m.toString(2).toCharArray();
	    BigInteger x = null;
	    // Encrypt bits
	    for(char bit : bit_array)
	    {
	    	System.out.print(bit);
	    	x = NTL.RandomBnd(pk.n);
	        if (bit == '1')
	        {
	        	enc_bits.add(pk.y.multiply(x.modPow(TWO, pk.n)).mod(pk.n));
	        }
	        else
	        {
	        	enc_bits.add(x.modPow(TWO, pk.n));
	        }
	    }
	    System.out.println(" ");
	    return enc_bits;
	}
	
	public static BigInteger decrypt(List<BigInteger> cipher, GMPrivateKey sk)
	{
		BigInteger e = null;
		String bits = "";
		for (BigInteger enc_bit: cipher)
		{
			e = NTL.jacobi(enc_bit, sk.p);
			if (e.equals(BigInteger.ONE))
			{
				bits += "0";
			}
			else
			{
				bits += "1";
			}
		}
	    return new BigInteger(bits, 2);
	}
}
