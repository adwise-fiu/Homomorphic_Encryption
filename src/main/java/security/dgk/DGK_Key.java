package security.dgk;

import java.math.BigInteger;

public interface DGK_Key 
{
	BigInteger getU();
	BigInteger getN();
	int getL();
}
