package security.generic;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;
import java.util.WeakHashMap;

import javax.crypto.BadPaddingException;

import security.DGK.DGKOperations;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

public class PHE_Core 
{
	// globally enable/disable use of blinding
	private final static boolean ENABLE_BLINDING = false;

	// cache for blinding parameters. Map<BigInteger, BlindingParameters>
	// use a weak hashmap so that cached values are automatically cleared
	// when the modulus is GC'ed
	private final static Map<BigInteger, BlindingParameters>
	blindingCache = new WeakHashMap<>();
	
	public static byte[] Paillier_encrypt(byte [] msg, PaillierPublicKey key)
			throws BadPaddingException 

	{
		BigInteger message = parseMsg(msg, key.getModulus());
		BigInteger cipher = PaillierCipher.encrypt(message, key);
		return toByteArray(cipher, getByteLength(key.getModulus()));
	}

	public static byte [] Paillier_decrypt(byte [] msg, PaillierPrivateKey key)
			throws BadPaddingException 
	{
		BigInteger cipher_text = parseMsg(msg, key.getModulus());
		BlindingRandomPair brp = null;
		BigInteger message = null;
		if (ENABLE_BLINDING)
		{
			message = PaillierCipher.decrypt(cipher_text, key);
			brp = getBlindingRandomPair(null, key.getN(), key.getN());
			cipher_text = cipher_text.multiply(brp.u).mod(key.getN());
			message = cipher_text.modPow(key.getN(), key.getModulus());
			message = message.multiply(brp.v).mod(key.getN());
			/*
			brp = getBlindingRandomPair(null, exp, n);
			cipher_text = cipher_text.multiply(brp.u).mod(key.n);
			message = cipher_text.modPow(exp, n);
			message = message.multiply(brp.v).mod(n);
			*/
		}
		else
		{
			message = PaillierCipher.decrypt(cipher_text, key);
		}
		return toByteArray(message, getByteLength(key.getModulus()));
	}

	public static byte[] DGK_encrypt(byte [] msg, DGKPublicKey key)
			throws BadPaddingException 

	{
		BigInteger message = parseMsg(msg, key.getN());
		BigInteger cipher = DGKOperations.encrypt(key, message);
		return toByteArray(cipher, getByteLength(key.getN()));
	}

	public static byte[] DGK_decrypt(byte [] msg, DGKPrivateKey key)
			throws BadPaddingException 
	{
		BigInteger cipher_text = parseMsg(msg, key.getN());
		BlindingRandomPair brp = null;
		BigInteger message = null;
		if (ENABLE_BLINDING)
		{
			message = DGKOperations.decrypt(cipher_text, key);		
			brp = getBlindingRandomPair(null, key.getN(), key.getN());
			cipher_text = cipher_text.multiply(brp.u).mod(key.getN());
			message = cipher_text.modPow(key.getN(), key.getN());
			message = message.multiply(brp.v).mod(key.getN());
			/*
			brp = getBlindingRandomPair(null, exp, n);
			cipher_text = cipher_text.multiply(brp.u).mod(key.n);
			message = cipher_text.modPow(exp, n);
			message = message.multiply(brp.v).mod(n);
			*/
		}
		else
		{
			message = DGKOperations.decrypt(cipher_text, key);
		}
		return toByteArray(message, getByteLength(key.getN()));
	}
	

	public static byte[] ElGamal_encrypt(byte [] msg, ElGamalPublicKey key)
			throws BadPaddingException 

	{
		/*
		BigInteger message = parseMsg(msg, key.n);
		BigInteger cipher = ElGamalCipher.encrypt(key, message);
		return toByteArray(cipher, getByteLength(key.n));
		*/
		return null;
	}

	public static byte[] ElGamal_decrypt(byte [] msg, ElGamalPrivateKey key)
			throws BadPaddingException 
	{
		/*
		BigInteger cipher_text = parseMsg(msg, key.n);
		BlindingRandomPair brp = null;
		BigInteger message = null;
		if (ENABLE_BLINDING)
		{
			message = ElGamalCipher.decrypt(cipher_text, key);
			brp = getBlindingRandomPair(null, exp, n);
			cipher_text = cipher_text.multiply(brp.u).mod(key.n);
			message = cipher_text.modPow(exp, n);
			message = message.multiply(brp.v).mod(n);
			
		}
		else
		{
			message = ElGamalCipher.decrypt(cipher_text, key);
		}
		return toByteArray(message, getByteLength(key.n));
		*/
		return null;
	}

	/**
	 * Return the encoding of this BigInteger that is exactly len bytes long.
	 * Prefix/strip off leading 0x00 bytes if necessary.
	 * Precondition: bi must fit into len bytes
	 */
	private static byte[] toByteArray(BigInteger bi, int len) 
	{
		byte[] b = bi.toByteArray();
		int n = b.length;
		if (n == len) 
		{
			return b;
		}
		// BigInteger prefixed a 0x00 byte for 2's complement form, remove it
		if ((n == len + 1) && (b[0] == 0)) 
		{
			byte[] t = new byte[len];
			System.arraycopy(b, 1, t, 0, len);
			return t;
		}
		// must be smaller
		assert (n < len);
		byte[] t = new byte[len];
		System.arraycopy(b, 0, t, (len - n), n);
		return t;
	}

	/**
	 * Parameters (u,v) for RSA Blinding.  This is described in the RSA
	 * Bulletin#2 (Jan 96) and other places:
	 *
	 *     ftp://ftp.rsa.com/pub/pdfs/bull-2.pdf
	 *
	 * The standard RSA Blinding decryption requires the public key exponent
	 * (e) and modulus (n), and converts ciphertext (c) to plaintext (p).
	 *
	 * Before the modular exponentiation operation, the input message should
	 * be multiplied by (u (mod n)), and afterward the result is corrected
	 * by multiplying with (v (mod n)).  The system should reject messages
	 * equal to (0 (mod n)).  That is:
	 *
	 *     1.  Generate r between 0 and n-1, relatively prime to n.
	 *     2.  Compute x = (c*u) mod n
	 *     3.  Compute y = (x^d) mod n
	 *     4.  Compute p = (y*v) mod n
	 *
	 * The Java APIs allows for either standard RSAPrivateKey or
	 * RSAPrivateCrtKey RSA keys.
	 *
	 * If the public exponent is available to us (e.g. RSAPrivateCrtKey),
	 * choose a random r, then let (u, v):
	 *
	 *     u = r ^ e mod n
	 *     v = r ^ (-1) mod n
	 *
	 * The proof follows:
	 *
	 *     p = (((c * u) ^ d mod n) * v) mod n
	 *       = ((c ^ d) * (u ^ d) * v) mod n
	 *       = ((c ^ d) * (r ^ e) ^ d) * (r ^ (-1))) mod n
	 *       = ((c ^ d) * (r ^ (e * d)) * (r ^ (-1))) mod n
	 *       = ((c ^ d) * (r ^ 1) * (r ^ (-1))) mod n  (see below)
	 *       = (c ^ d) mod n
	 *
	 * because in RSA cryptosystem, d is the multiplicative inverse of e:
	 *
	 *    (r^(e * d)) mod n
	 *       = (r ^ 1) mod n
	 *       = r mod n
	 *
	 * However, if the public exponent is not available (e.g. RSAPrivateKey),
	 * we mitigate the timing issue by using a similar random number blinding
	 * approach using the private key:
	 *
	 *     u = r
	 *     v = ((r ^ (-1)) ^ d) mod n
	 *
	 * This returns the same plaintext because:
	 *
	 *     p = (((c * u) ^ d mod n) * v) mod n
	 *       = ((c ^ d) * (u ^ d) * v) mod n
	 *       = ((c ^ d) * (u ^ d) * ((u ^ (-1)) ^d)) mod n
	 *       = (c ^ d) mod n
	 *
	 * Computing inverses mod n and random number generation is slow, so
	 * it is often not practical to generate a new random (u, v) pair for
	 * each new exponentiation.  The calculation of parameters might even be
	 * subject to timing attacks.  However, (u, v) pairs should not be
	 * reused since they themselves might be compromised by timing attacks,
	 * leaving the private exponent vulnerable.  An efficient solution to
	 * this problem is update u and v before each modular exponentiation
	 * step by computing:
	 *
	 *     u = u ^ 2
	 *     v = v ^ 2
	 *
	 * The total performance cost is small.
	 */
	private final static class BlindingRandomPair 
	{
		public final BigInteger u;
		public final BigInteger v;
		BlindingRandomPair(BigInteger u, BigInteger v) 
		{
			this.u = u;
			this.v = v;
		}
	}

	// temporary, used by RSACipher and RSAPadding. Move this somewhere else
	public static byte[] convert(byte[] b, int ofs, int len) 
	{
		if ((ofs == 0) && (len == b.length)) 
		{
			return b;
		} 
		else 
		{
			byte[] t = new byte[len];
			System.arraycopy(b, ofs, t, 0, len);
			return t;
		}
	}

	/**
	 * Parse the msg into a BigInteger and check against the modulus n.
	 */
	private static BigInteger parseMsg(byte[] msg, BigInteger n)
			throws BadPaddingException 
	{
		BigInteger m = new BigInteger(1, msg);
		if (m.compareTo(n) >= 0) 
		{
			throw new BadPaddingException("Message is larger than modulus");
		}
		return m;
	}

	/**
	 * Set of blinding parameters for a given RSA key.
	 *
	 * The RSA modulus is usually unique, so we index by modulus in
	 * {@code blindingCache}.  However, to protect against the unlikely
	 * case of two keys sharing the same modulus, we also store the public
	 * or the private exponent.  This means we cannot cache blinding
	 * parameters for multiple keys that share the same modulus, but
	 * since sharing moduli is fundamentally broken and insecure, this
	 * does not matter.
	 */
	private final static class BlindingParameters 
	{
		private final static BigInteger BIG_TWO = BigInteger.valueOf(2L);

		// RSA public exponent
		private final BigInteger e;

		// hash code of RSA private exponent
		private final BigInteger d;

		// r ^ e mod n (CRT), or r mod n (Non-CRT)
		private BigInteger u;

		// r ^ (-1) mod n (CRT) , or ((r ^ (-1)) ^ d) mod n (Non-CRT)
		private BigInteger v;

		// e: the public exponent
		// d: the private exponent
		// n: the modulus
		// Build Blinding Parameters
		BlindingParameters(BigInteger e, BigInteger d, BigInteger n) 
		{
			this.u = null;
			this.v = null;
			this.e = e;
			this.d = d;

			int len = n.bitLength();
			SecureRandom random = new SecureRandom();
			u = new BigInteger(len, random).mod(n);
			// Although the possibility is very much limited that u is zero
			// or is not relatively prime to n, we still want to be careful
			// about the special value.
			//
			// Secure random generation is expensive, try to use BigInteger.ONE
			// this time if this new generated random number is zero or is not
			// relatively prime to n.  Next time, new generated secure random
			// number will be used instead.
			if (u.equals(BigInteger.ZERO)) 
			{
				u = BigInteger.ONE;     // use 1 this time
			}

			try
			{
				// The call to BigInteger.modInverse() checks that u is
				// relatively prime to n.  Otherwise, ArithmeticException is
				// thrown.
				v = u.modInverse(n);
			} 
			catch (ArithmeticException ae) 
			{
				// if u is not relatively prime to n, use 1 this time
				u = BigInteger.ONE;
				v = BigInteger.ONE;
			}
			if (e != null) 
			{
				u = u.modPow(e, n);   // e: the public exponent
				// u: random ^ e
				// v: random ^ (-1)
			} 
			else 
			{
				v = v.modPow(d, n);   // d: the private exponent
				// u: random
				// v: random ^ (-d)
			}
		}

		// return null if need to reset the parameters
		private BlindingRandomPair getBlindingRandomPair(
				BigInteger e, BigInteger d, BigInteger n) 
		{

			if ((this.e != null && this.e.equals(e)) ||
					(this.d != null && this.d.equals(d))) 
			{

				BlindingRandomPair brp = null;
				synchronized (this)
				{
					if (!u.equals(BigInteger.ZERO) &&
							!v.equals(BigInteger.ZERO)) 
					{

						brp = new BlindingRandomPair(u, v);
						if (u.compareTo(BigInteger.ONE) <= 0 ||
								v.compareTo(BigInteger.ONE) <= 0) 
						{

							// need to reset the random pair next time
							u = BigInteger.ZERO;
							v = BigInteger.ZERO;
						} 
						else 
						{
							u = u.modPow(BIG_TWO, n);
							v = v.modPow(BIG_TWO, n);
						}
					} // Otherwise, need to reset the random pair.
				}
				return brp;
			}
			return null;    
		}
	}

	/**
	 * Return the number of bytes required to store the magnitude byte[] of
	 * this BigInteger. Do not count a 0x00 byte toByteArray() would
	 * prefix for 2's complement form.
	 */
	public static int getByteLength(BigInteger b) 
	{
		int n = b.bitLength();
		int n_bytes = (n + 7) >> 3;
		return n_bytes;
	}

	protected static BlindingRandomPair getBlindingRandomPair(BigInteger e, BigInteger d, BigInteger n) 
	{
		BlindingParameters bps = null;
		synchronized (blindingCache) 
		{
			bps = blindingCache.get(n);
		}

		if (bps == null) 
		{
			bps = new BlindingParameters(e, d, n);
			synchronized (blindingCache) 
			{
				blindingCache.putIfAbsent(n, bps);
			}
		}

		BlindingRandomPair brp = bps.getBlindingRandomPair(e, d, n);
		if (brp == null)
		{
			// need to reset the blinding parameters
			bps = new BlindingParameters(e, d, n);
			synchronized (blindingCache)
			{
				blindingCache.replace(n, bps);
			}
			brp = bps.getBlindingRandomPair(e, d, n);
		}
		return brp;
	}
}