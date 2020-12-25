package security.paillier;

import java.math.BigInteger;

public interface PaillierKey 
{
	public BigInteger getN();
	public BigInteger getModulus();
}
