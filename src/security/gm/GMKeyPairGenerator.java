package security.gm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import security.generic.NTL;

public class GMKeyPairGenerator extends KeyPairGeneratorSpi
{
	// k2 controls the error probability of the primality testing algorithm
	// (specifically, with probability at most 2^(-k2) a NON prime is chosen).
	private final static int CERTAINTY = 40;
	private int keysize = 1024;
	private SecureRandom rnd = null;

	// https://medium.com/coinmonks/probabilistic-encryption-using-the-goldwasser-micali-gm-method-7f9893a93ac9
	public void initialize(int keysize, SecureRandom random) 
	{
		this.keysize = keysize;
		this.rnd = random;
	}

	public KeyPair generateKeyPair() 
	{
		if(rnd == null)
		{
			rnd = new SecureRandom();
		}
		
	    BigInteger p = new BigInteger(keysize/2, CERTAINTY, rnd);
	    BigInteger q = new BigInteger(keysize/2, CERTAINTY, rnd);
	    BigInteger y = null;
	    /*
	    while (p == q)
	    {
	        p2 = big_prime(prime_size);
	    }
	    */
	    y = pseudosquare(p, q);
	    BigInteger n = p.multiply(q);
	    return new KeyPair(new GMPublicKey(n, y), new GMPrivateKey(p, q));
	}
	
	public BigInteger pseudosquare(BigInteger p, BigInteger q)
	{
		BigInteger a = quadratic_non_residue(p);
		BigInteger b = quadratic_non_residue(q);
	    return gauss_crt(a, b, p, q);
	}

	// a = {a, b} and m = {p, q}
	public BigInteger gauss_crt(BigInteger a, BigInteger b, BigInteger p, BigInteger q)
	{
	    // return x in ' x = a mod m'.
	    // BigInteger modulus = reduce(lambda a,b: a*b, m);
		BigInteger modulus = p.multiply(q);
	    BigInteger M = null;
	    BigInteger multi_1 = null;
	    BigInteger multi_2 = null;
	    BigInteger inverse = null;
	    
	    M = modulus.divide(p);
	    inverse = xeuclid_inverse(M, p);
	    multi_1 = inverse.multiply(M.mod(modulus));
	    
	    M = modulus.divide(q);
	    inverse = xeuclid_inverse(M, q);
	    multi_2 = inverse.multiply(M.mod(modulus));
	    
	    BigInteger result = BigInteger.ZERO;
	    result = result.add(multi_1).multiply(a).mod(modulus);
	    result = result.add(multi_2).multiply(b).mod(modulus);
	    return result;
	}
	
	public BigInteger xeuclid_inverse(BigInteger a, BigInteger b)
	{
		return xeuclid(a, b).get(1);
	}
	
	public List<BigInteger> xeuclid(BigInteger a, BigInteger b)
	{
	    // return gcd(a,b), x and y in 'gcd(a,b) = ax + by'.   
	    BigInteger [] x = new BigInteger[2];
	    x[0] = BigInteger.ONE;
	    x[1] = BigInteger.ZERO;
	    BigInteger [] y = new BigInteger[2];
	    y[0] = BigInteger.ZERO;
	    y[1] = BigInteger.ONE;
	    int sign = 1;
	    BigInteger q, r;
	    while (!b.equals(BigInteger.ZERO))
	    {
	    	// q = res[0] and r = res[1]
	    	BigInteger [] res = a.divideAndRemainder(b);
	    	q = res[0];
	    	r = res[1];
	        a = b;
	        b = r;
	        x[1] = q.multiply(x[1]).add(x[0]);
	        x[0] = x[1];
	        y[1] = q.multiply(y[1]).add(y[0]);
	        y[0] = y[1];
	        sign = -sign;
	    }
	    List<BigInteger> answer = new ArrayList<BigInteger>();
	    answer.add(a);
	    answer.add(x[0].multiply(BigInteger.valueOf(sign)));
	    answer.add(y[0].multiply(BigInteger.valueOf(-1 * sign)));
	    return answer;
	}
    
    //-------------------Relevent to GM----------------------

    public BigInteger quadratic_non_residue(BigInteger p)
    {
    	BigInteger a = BigInteger.ZERO;
    	BigInteger neg_one = new BigInteger("-1");
    	while (!NTL.jacobi(a, p).equals(neg_one))
    	{
    		// a = randint(1, p) --> [1, p]
    		// x = pseudo-random number in the range [0..n-1]
    		a = NTL.RandomBnd(p);
    	}
    	return a;
    }
}
