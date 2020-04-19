package security.gm;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

public class GMPrivateKey implements Serializable, PrivateKey
{
	private static final long serialVersionUID = -6003066379615503599L;
	protected BigInteger p;
	protected BigInteger q;
	
	protected GMPrivateKey(BigInteger p, BigInteger q)
	{
		this.p = p;
		this.q = q;
	}
	
	public String getAlgorithm() 
	{
		return "Goldwaser-Micali";
	}

	public String getFormat()
	{
		return "PKCS#8";
	}

	public byte[] getEncoded() 
	{
		return null;
	}

}
