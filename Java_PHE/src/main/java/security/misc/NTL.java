package security.misc;

/*

This is the Java implementation of the C++ NTL Library
Please refer to this site for NTL documentation:
http://www.shoup.net/ntl/doc/tour.html
http://www.shoup.net/ntl/doc/ZZ.txt

Credits to Andrew Quijano for code conversion 
and Samet Tonyali for helping on revising the code/debugging it.

Feel free to use this code as you like.
 */

import java.math.BigInteger;
import java.security.SecureRandom;

public class NTL implements CipherConstants
{
	private static SecureRandom rnd = new SecureRandom();

	// AKS Test
	// array used to store coefficients . 
	static long c[] = new long[100]; 

	// function to calculate the coefficients 
	// of (x - 1)^n - (x^n - 1) with the help 
	// of Pascal's triangle . 
	static void coef(long n) 
	{ 
		c[0] = 1; 
		for (int i = 0; i < n; c[0] = -c[0], i++) 
		{
			c[1 + i] = 1; 
			for (int j = i; j > 0; j--) 
			{
				c[j] = c[j - 1] - c[j]; 
			}
		} 
	} 

	// function to check whether 
	// the number is prime or not 
	static boolean isPrime(int n) 
	{ 
		// Calculating all the coefficients by 
		// the function coef and storing all 
		// the coefficients in c array . 
		coef(n); 

		// subtracting c[n] and adding c[0] by 1 
		// as ( x - 1 )^n - ( x^n - 1), here we 
		// are subtracting c[n] by 1 and adding 
		// 1 in expression. 
		c[0]++; 
		c[n]--; 

		// checking all the coefficients whether 
		// they are divisible by n or not. 
		// if n is not prime, then loop breaks 
		// and (i > 0). 
		int i = n; 
		while ((i--) > 0 && c[i] % n == 0); 

		// Return true if all coefficients are 
		// divisible by n. 
		return i < 0; 
	}

	public static BigInteger POSMOD(BigInteger x, BigInteger n)
	{
		BigInteger answer = x.mod(n).add(n).mod(n);
		return answer;
	}

	public static long POSMOD(long x, long n)
	{
		return ((x % n) + n) % n;
	}

	public static BigInteger POSMOD(long x, BigInteger n)
	{
		return POSMOD(BigInteger.valueOf(x), n);
	}

	// Ensure it is n-bit Large number and positive as well
	public static BigInteger generateXBitRandom (int bits)
	{
		BigInteger r = new BigInteger(bits, rnd);
		r = r.setBit(bits - 1);
		return r;
	}

	/*
	void RandomBnd(ZZ& x, const ZZ& n);
	ZZ RandomBnd(const ZZ& n);
	void RandomBnd(long& x, long n);
	long RandomBnd(long n);
	x = pseudo-random number in the range [0..n-1], or 0 if n <= 0
	 */

	public static BigInteger RandomBnd(long n)
	{
		return RandomBnd(BigInteger.valueOf(n));
	}

	public static BigInteger RandomBnd(BigInteger n)
	{
		if (n.signum() <= 0)
		{
			return BigInteger.ZERO;
		}
		BigInteger r;
		do
		{
			r = new BigInteger(n.bitLength(), rnd);
		}
		while (r.signum()== -1 || r.compareTo(n) >= 0);
		// 0 <= r <= n - 1
		// if r is negative or r >= n, keep generating random numbers
		return r;
	}

	// https://medium.com/coinmonks/probabilistic-encryption-using-the-goldwasser-micali-gm-method-7f9893a93ac9
	public static BigInteger jacobi(BigInteger a, BigInteger n)
	{
		if (a.compareTo(NEG_ONE) <= 0 || n.mod(TWO).equals(BigInteger.ZERO)) 
		{
			throw new IllegalArgumentException("Invalid value. k = " + a + ", n = " + n);
		}
		a = a.mod(n);
		BigInteger jacobi = BigInteger.ONE;
		while (a.compareTo(BigInteger.ZERO) == 1) 
		{
			while (a.mod(TWO).equals(BigInteger.ZERO)) 
			{
				a = a.divide(TWO);
				BigInteger r = n.mod(EIGHT);
				if ( r.equals(THREE) || r.equals(FIVE) ) 
				{
					jacobi = jacobi.multiply(NEG_ONE);
				}
			}
			BigInteger temp = n;
			n = a;
			a = temp;
			if ( a.mod(FOUR).equals(THREE) && n.mod(FOUR).equals(THREE) ) 
			{
				jacobi = jacobi.multiply(NEG_ONE);
			}
			a = a.mod(n);
		}
		if (n.equals(BigInteger.ONE)) 
		{
			return jacobi;
		}
		return BigInteger.ZERO;
	}

	public static BigInteger quadratic_non_residue(BigInteger p)
	{
		BigInteger a = BigInteger.ZERO;
		while (!NTL.jacobi(a, p).equals(NEG_ONE))
		{
			// a = randint(1, p) --> [1, p]
			// x = pseudo-random number in the range [0..n-1]
			a = NTL.RandomBnd(p);
		}
		return a;
	}
	
	public static BigInteger quadratic_non_residue(BigInteger p, BigInteger q)
	{
		BigInteger a = NTL.RandomBnd(p);
		while (true)
		{
			if(NTL.jacobi(a, p).equals(NEG_ONE))
			{
				if(NTL.jacobi(a, q).equals(NEG_ONE))
				{
					break;
				}
			}
			a = NTL.RandomBnd(p);
		}
		return a;
	}
	
	/*
    long bit(const ZZ& a, long k);
    long bit(long a, long k);
    returns bit k of |a|, position 0 being the low-order bit.
    If  k < 0 or k >= NumBits(a), returns 0.
	 */

	public static int bit(BigInteger a, long k)
	{
		//If the value k (location of bit is bigger than a
		if (k >= a.bitLength())
		{
			return 0;
		}
		if (k < 0)
		{
			return 0;
		}
		String bit = a.toString(2);//get it in Binary
		if (bit.charAt((int) k)== '0')
		{
			return 0;
		}
		else
		{
			return 1;
		}
	}

	public static int bit(long a, long k)
	{
		return bit(BigInteger.valueOf(a), k);
	}

}