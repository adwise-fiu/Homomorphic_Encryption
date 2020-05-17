package security.paillier;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

import security.generic.CipherConstants;

public class PaillierKeyPairGenerator extends KeyPairGeneratorSpi implements CipherConstants
{
	// k2 controls the error probability of the primality testing algorithm
	// (specifically, with probability at most 2^(-k2) a NON prime is chosen).
	private final static int CERTAINTY = 40;
	private int keysize = 1024;
	private SecureRandom rnd = null;
	
	public void initialize(int keysize, SecureRandom random) 
	{
		this.rnd = random;
		if (keysize % 2 != 0)
		{
			throw new IllegalArgumentException("NUMBER OF BITS SHOULD BE EVEN!");
		}
		
		// I will NOT allow weaker than 1024 bit keys!
		if (keysize < 1024)
		{
			return;
		}		
		this.keysize = keysize;
	}

	public KeyPair generateKeyPair() 
	{
		if (this.rnd == null)
		{
			rnd = new SecureRandom();
		}
		
		// Chooses a random prime of length k2. The probability that
		// p is not prime is at most 2^(-k2)
		BigInteger p = new BigInteger(keysize/2, CERTAINTY, rnd);
		BigInteger q = new BigInteger(keysize/2, CERTAINTY, rnd);

		BigInteger n = p.multiply(q); // n = pq
		BigInteger modulus = n.multiply(n); // modulous = n^2
		
		// Modifications to the Private key
		BigInteger lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		BigInteger mu = lambda.modInverse(n);
	
		// For signature
		// Build base g \in Z_{n^2} with order n
		BigInteger g = TWO;
		g = find_g(g, lambda, modulus, n);
		
		// Beware of flaw with Paillier if g^{lambda} = 1 (mod n^2)
		while(g.modPow(lambda, modulus).equals(BigInteger.ONE))
		{
			g = find_g(g.add(BigInteger.ONE), lambda, modulus, n);
		}
		
		BigInteger gcd = p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE));
		BigInteger alpha = find_alpha(lambda.divide(gcd), modulus);
		
		PaillierPublicKey pk = new PaillierPublicKey(this.keysize, n, modulus, g);
		PaillierPrivateKey sk = new PaillierPrivateKey(this.keysize, n, modulus, lambda, mu, g, alpha);
		
		System.out.println("Completed building Paillier Key Pair!");
		return new KeyPair(pk, sk);
	}
	
	// Find the smallest divisor!
    // Find alpha
	// alpha | lcm(p - 1, q - 1)
	private static BigInteger find_alpha(BigInteger LCM, BigInteger modulus) 
	{
		BigInteger alpha = TWO;
		while(true)
		{
			if(LCM.mod(alpha).compareTo(BigInteger.ZERO) == 0)
			{
				return alpha;
			}
			alpha = alpha.add(BigInteger.ONE);
		}
	}
	
	// Build generator
	private static BigInteger find_g(BigInteger g, BigInteger lambda, BigInteger modulus, BigInteger n)
	{
		while(true)
		{
			if(PaillierCipher.L(g.modPow(lambda, modulus), n).gcd(n).equals(BigInteger.ONE))
			{
				return g;		
			}
			g = g.add(BigInteger.ONE);
		}
	}
}
