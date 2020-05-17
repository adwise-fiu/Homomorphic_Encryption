package security.gm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import security.generic.CipherConstants;
import security.generic.NTL;

public class GMKeyPairGenerator extends KeyPairGeneratorSpi implements CipherConstants
{
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
	    BigInteger y = pseudosquare(p, q);
	    BigInteger n = p.multiply(q);
	    return new KeyPair(new GMPublicKey(n, y), new GMPrivateKey(p, q));
	}
	
	public BigInteger pseudosquare(BigInteger p, BigInteger q)
	{
		BigInteger a = NTL.quadratic_non_residue(p);
		BigInteger b = NTL.quadratic_non_residue(q);
		BigInteger [] a_list = {a, b};
		BigInteger [] n_list = {p, q};
	    return gauss_crt(a_list, n_list);
	}

	// a = {a, b} and m = {p, q}
	public BigInteger gauss_crt(BigInteger [] a, BigInteger [] n)
	{
		BigInteger x = BigInteger.ZERO;
		BigInteger N = n[0].multiply(n[1]);
		BigInteger n_i = null;
		BigInteger m_i = null;
		for (int i = 0; i < n.length; i++)
		{
	        n_i = N.divide(n[i]);
	        // p and q are primes,
	        // so n_i^(-1) mod n = n_i^(n - 2) mod n
	        m_i = x.modPow(n[i].subtract(new BigInteger("2")), n[i]);
	        x = x.add(a[i].multiply(n_i).multiply(m_i).mod(n[i]));
		}
		return x;
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
    
}
