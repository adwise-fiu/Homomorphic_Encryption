package security.generic;

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
import java.util.ArrayList;

public class NTL implements CipherConstants
{
    private static SecureRandom rnd = new SecureRandom();
    
    public static boolean AKSTest(BigInteger p)
    {
    	/*
        (x-1)^p - (x^p - 1)
        Test if p divides all the coefficients
        excluding the first and last term of (x-1)^p
        If it can divide all of them then p is a prime

        Using Binomial Theorem, I obtain the coefficients of all
        terms from the expansion (x-1)^p
        */
    	ArrayList<BigInteger> coeff = BinomialTheorem(p);
        coeff.remove(0); //Remove first term
        coeff.remove(coeff.remove(coeff.size()-1)); //Remove last term

        for (int i=0;i<coeff.size();i++)
        {
            if (!coeff.get(i).mod(p).equals(BigInteger.ZERO))
            {
                return false;
            }
        }
        return true;
    }
    
    //AKS-Test, I can use binomial theorem
    public static ArrayList<BigInteger> BinomialTheorem (BigInteger x)
    {
        ArrayList<BigInteger> coeff = new ArrayList<BigInteger>();
		/*
		 * 	Binomial Theorem: Choose
		 * 	n	n	n	...	n
		 * 	0	1	2	...	n
		 */
        BigInteger start = BigInteger.ZERO;
        while (! (start.equals(x.add(BigInteger.ONE))) )
        {
            coeff.add(nCr(x,start));
            start = start.add(BigInteger.ONE);
        }
        return coeff;
    }

    public static BigInteger nCr (BigInteger n, BigInteger r)
    {
    	BigInteger nCr = factorial(n);
        nCr = nCr.divide(factorial(r));
        nCr = nCr.divide(factorial(n.subtract(r)));
        //nCr = n!/r!(n-r)!
        //or (n * n-1 * ... r+1)/(n-r)!
        return nCr;
    }

    public static BigInteger factorial(BigInteger x)
    {
        BigInteger result = BigInteger.ONE;
        BigInteger n = x;
        while (!n.equals(BigInteger.ZERO))
        {
            result = result.multiply(n);
            n = n.subtract(BigInteger.ONE);
        }
        return result;
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
        //System.out.println(r.bitLength());
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
    
    // https://medium.com/coinmonks/probabilistic-encryption-using-the-goldwasser-micali-gm-method-7f9893a93ac9
    public static BigInteger jacobi(BigInteger a, BigInteger n)
    {
    	if (a.equals(BigInteger.ZERO))
    	{
    		return BigInteger.ZERO;
    	}
    	if (a.equals(BigInteger.ONE))
    	{
    		return BigInteger.ONE;
    	}
    	BigInteger e = BigInteger.ZERO;
    	BigInteger a1 = a;
    	while (a1.mod(TWO).equals(BigInteger.ZERO))
    	{
    		e = e.add(BigInteger.ONE);
    		a1 = a1.divide(TWO);
    	}

    	// assert 2**e * a1 == a;
    	BigInteger s = BigInteger.ZERO;
    	BigInteger temp = n.mod(EIGHT);
    	
    	if (e.mod(TWO).equals(BigInteger.ZERO))
    	{
    		s = BigInteger.ONE;
    	}
    	// n % 8 in {1, 7}
    	else if (temp.equals(BigInteger.ONE) || temp.equals(SEVEN))
    	{
    		s = BigInteger.ONE;
    	}
    	// n % 8 in {3, 5}
    	else if (temp.equals(THREE) || temp.equals(FIVE))
    	{
    		s = new BigInteger("-1");
    	}

    	if (n.mod(FOUR).equals(THREE) && a1.mod(FOUR).equals(THREE))
    	{
    		s = s.multiply(new BigInteger("-1"));
    	}
    	BigInteger n1 = n.mod(a1);
    	if (a1.equals(BigInteger.ONE))
    	{
    		return s;
    	}
    	else
    	{
    		return s.multiply(jacobi(n1, a1));
    	}
    }
    
    public static BigInteger quadratic_non_residue(BigInteger p)
    {
    	BigInteger a = BigInteger.ZERO;
    	while (!NTL.jacobi(a, p).equals(neg_one))
    	{
    		// a = randint(1, p) --> [1, p]
    		// x = pseudo-random number in the range [0..n-1]
    		a = NTL.RandomBnd(p);
    	}
    	return a;
    }
}