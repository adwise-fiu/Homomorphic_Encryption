package security.socialistmillionaire;

import java.math.BigInteger;
import java.security.SecureRandom;

public interface socialist_millionaires 
{	
	final static BigInteger TWO = new BigInteger("2");
	final SecureRandom rnd = new SecureRandom();
	final static int SIGMA = 80;
	final static int BILLION = BigInteger.TEN.pow(9).intValue();
}
