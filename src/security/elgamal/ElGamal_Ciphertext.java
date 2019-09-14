package security.elgamal;

import java.io.Serializable;
import java.math.BigInteger;

public class ElGamal_Ciphertext implements Serializable
{
	private static final long serialVersionUID = -4168027417302369803L;
	public final BigInteger gr; //(g^r)
	public final BigInteger hrgm; //(m * h^r) OR (g^m * h^r)
	
	public ElGamal_Ciphertext(BigInteger gr, BigInteger mhr)
	{
		this.gr = gr;
		this.hrgm = mhr;
	}
	
	// used for signatures
	public BigInteger getA()
	{
		return this.gr;
	}
	
	public BigInteger getB()
	{
		return this.hrgm;
	}
}
