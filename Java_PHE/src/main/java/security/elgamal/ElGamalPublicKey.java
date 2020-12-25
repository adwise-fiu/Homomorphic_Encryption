package security.elgamal;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public final class ElGamalPublicKey implements Serializable, PublicKey, ElGamal_Key
{
	private static final long serialVersionUID = -6796919675914392847L;
	protected final BigInteger p;
	protected final BigInteger g;
	protected final BigInteger h;
	public boolean ADDITIVE;

	public ElGamalPublicKey(BigInteger p, BigInteger g, BigInteger h, boolean ADDITIVE)
	{
		this.p = p;
		this.g = g;
		this.h = h;
		this.ADDITIVE = ADDITIVE;
	}

	public String getAlgorithm() 
	{
		return "ElGamal";
	}

	public String getFormat() 
	{
		return "X.509";
	}

	public byte[] getEncoded() 
	{
		return null;
	}

	public BigInteger getP() 
	{
		return this.p;
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

	public String toString()
	{
		String answer = "";
		answer += "p=" + this.p + '\n';
		answer += "g=" + this.g + '\n';
		answer += "h=" + this.h + '\n';
		return answer;
	}
}
