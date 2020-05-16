package security.DGK;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.HashMap;

import security.generic.CipherConstants;

public final class DGKPublicKey implements Serializable, DGK_Key, PublicKey, Runnable, CipherConstants
{
	private static final long serialVersionUID = -1613333167285302035L;
	
	protected final BigInteger n;
	protected final BigInteger g;
	protected final BigInteger h;
	protected final long u;
	protected final BigInteger bigU;
	protected final HashMap <Long, BigInteger> gLUT = new HashMap<Long, BigInteger>();
	protected final HashMap <Long, BigInteger> hLUT = new HashMap<Long, BigInteger>();
	
	// Key Parameters
	protected final int l;
	protected final int t;
	protected final int k;

	//DGK Constructor with ALL parameters
	public DGKPublicKey(BigInteger n, BigInteger g, BigInteger h, BigInteger u,
						int l, int t, int k)
	{
		this.n = n;
		this.g = g;
		this.h = h;
		this.u = u.longValue();
		this.bigU = u;
		this.l = l; 
		this.t = t;
		this.k = k;
	}
		
	private void readObject(ObjectInputStream aInputStream)
			throws ClassNotFoundException,IOException
	{
		aInputStream.defaultReadObject();
	}

	private void writeObject(ObjectOutputStream aOutputStream) throws IOException
	{
		aOutputStream.defaultWriteObject();
	}

	public BigInteger ZERO()
	{
		return DGKOperations.encrypt(this, 0);
	}
	
	public BigInteger ONE()
	{
		return DGKOperations.encrypt(this, 1);
	}

	public String getAlgorithm() 
	{
		return "DGK";
	}
	
    public String toString()
    {
    	String answer = "";
    	answer += "n: " + n + ", " + '\n';
    	answer += "g: " + g + ", " + '\n';
    	answer += "h: " + h + ", " + '\n';
    	answer += "u: " + bigU + ", " + '\n';
    	answer += "l: " + l + ", " + '\n';
    	answer += "t: " + t + ", " + '\n';
    	answer += "k: " + k + ", " + '\n';
    	return answer;
    }
    
	public String getFormat() 
	{
		return "X.509";
	}

	public byte[] getEncoded() 
	{
		return null;
	}

	public void run() 
	{
		this.generatehLUT();
		this.generategLUT();
	}
	
	private void generatehLUT()
	{		
		for (long i = 0; i < 2 * t; ++i)
		{
			// e = 2^i (mod n)
			// h^{2^i (mod n)} (mod n)
			// f(i) = h^{2^i}(mod n)
			BigInteger e = TWO.pow((int) i).mod(this.n);
			this.hLUT.put(i, this.h.modPow(e, this.n));
		}
	}
	
	private void generategLUT()
	{	
		for (long i = 0; i < this.u; ++i)
		{
			BigInteger out = this.g.modPow(BigInteger.valueOf(i), this.n);
			this.gLUT.put(i, out);
		}
	}

	public BigInteger getU() 
	{
		return this.bigU;
	}

	public BigInteger getN() 
	{
		return this.n;
	}
	
	public int getL()
	{
		return this.l;
	}
}