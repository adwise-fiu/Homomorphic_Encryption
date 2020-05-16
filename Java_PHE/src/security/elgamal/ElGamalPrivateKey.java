package security.elgamal;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import security.generic.CipherConstants;

public final class ElGamalPrivateKey implements ElGamal_Key, Serializable, PrivateKey, Runnable, CipherConstants
{
	//Private Key parameters
	protected final BigInteger x;
    protected final Map <BigInteger, BigInteger> LUT;
	
	// Taken from ElGamal Public Key
    protected final BigInteger p;
	protected final BigInteger g;
    protected final BigInteger h;
	
    private static final long serialVersionUID = 9160045368787508459L;
    
	public ElGamalPrivateKey(BigInteger p, BigInteger x, BigInteger g, BigInteger h)
	{
		this.p = p;
		this.x = x;
		this.g = g;
		this.h = h;
		this.LUT = new HashMap<BigInteger, BigInteger>(FIELD_SIZE.intValue(), (float) 1.0);
		this.decrypt_table();
	}
	
	public String getAlgorithm()
	{
		return "ElGamal";
	}

	public String getFormat() 
	{
		return "PKCS#8";
	}

	public byte[] getEncoded() 
	{
		return null;
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
    
    // Generate Lookup Table, plain text space is [0, p - 1)
    private void decrypt_table() 
	{
		// Get maximum size of x - y + r + 2^l
    	// Assume maximum value is u: biggest value in DGK which is closest prime from 2^l l = 16 default.
		BigInteger decrypt_size = FIELD_SIZE.add(FIELD_SIZE).subtract(TWO).add(TWO.pow(16));
    	long start_time = System.nanoTime();
    	System.out.println("Building Lookup Table g^m --> m for ElGamal");
    	BigInteger message = BigInteger.ZERO;
		while (!message.equals(decrypt_size))
		{
			BigInteger gm = this.g.modPow(message, this.p);
			this.LUT.put(gm, message);
			message = message.add(BigInteger.ONE);
		}
		
		// For negative numbers, go from p - 2 and go down a bit
		message = this.p.subtract(TWO);
		while (!message.equals(this.p.subtract(BigInteger.TEN)))
		{
			BigInteger gm = this.g.modPow(message, this.p);
			this.LUT.put(gm, message);
			message = message.subtract(BigInteger.ONE);
		}
    	System.out.println("Finished Building Lookup Table g^m --> m for ElGamal in " + 
		(System.nanoTime() - start_time)/BigInteger.TEN.pow(9).longValue() + " seconds");
	}

	public void run() 
	{
		decrypt_table();
	}
	
	public String toString()
	{
    	String answer = "";
    	answer += "p=" + this.p + '\n';
    	answer += "g=" + this.g + '\n';
    	answer += "h=" + this.h + '\n';
    	//answer += "s=" + this.x + '\n';
    	return answer;
	}

	public BigInteger getP() 
	{
		return this.p;
	}
}
