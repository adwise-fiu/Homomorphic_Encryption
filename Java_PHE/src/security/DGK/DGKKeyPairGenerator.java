package security.DGK;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

import security.generic.CipherConstants;
import security.generic.NTL;

public final class DGKKeyPairGenerator extends KeyPairGeneratorSpi implements CipherConstants
{
	// Default parameters
	private int l = 16;
	private int t = 160;
	private int k = 1024;
	private boolean no_skip_public_key_maps = true;
	private SecureRandom rnd = null;
	
	public DGKKeyPairGenerator(int l, int t, int k)
	{
		// First check that all the parameters of the KeyPair are coherent throw an exception otherwise
		if (l < 0 || l > 32)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: plaintext space must be less than 32 bits");
		}

		if (l > t || t > k)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have l < k < t");
		}

		if (k/2 < t + l + 1)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l");
		}

		if (t % 2 != 0)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: t must be divisible by 2 ");
		}
		
		this.l = l;
		this.t = t;
		this.k = k;
		this.initialize(k, null);
	}

	public int getL()
	{
		return l;
	}
	
	public void setL(int l)
	{
		if (l < 0 || l > 32)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: plaintext space must be less than 32 bits");
		}

		if (l > this.t || this.t > this.k)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have l < k < t");
		}

		if (this.k/2 < this.t + l + 1)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l");
		}
		this.l = l;
	}
	
	public int getT()
	{
		return t;
	}
	
	public void setT(int t)
	{
		if (this.l > t || t > this.k)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have l < k < t");
		}

		if (this.k/2 < t + this.l + 1)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l");
		}

		if (t % 2 != 0)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: t must be divisible by 2 ");
		}
		this.t = t;
	}
	
	public int getK()
	{
		return k;
	}
	
	public void setK(int k)
	{
		if (this.l > this.t || this.t > k)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have l < k < t");
		}

		if (k/2 < this.t + this.l + 1)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l");
		}
		this.k = k;
	}
	
	public void setSkip(boolean no_skip_public_key_maps)
	{
		this.no_skip_public_key_maps = no_skip_public_key_maps;
	}
	
	public boolean getSkip()
	{
		return no_skip_public_key_maps;
	}

	public void initialize(int k, SecureRandom random) 
	{
		if (this.l > this.t || this.t > k)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have l < k < t");
		}

		if (k/2 < this.t + this.l + 1)
		{
			throw new IllegalArgumentException("DGK Keygen Invalid parameters: we must have k > k/2 < t + l");
		}
		this.k = k;
		this.rnd = random;
	}

	public KeyPair generateKeyPair() 
	{
		long start_time = System.nanoTime();
		if(this.rnd == null)
		{
			this.rnd = new SecureRandom();
		}
		
		DGKPublicKey pubKey = null;
		DGKPrivateKey privkey = null;
		
		System.out.println("Generating Keys...");

		BigInteger p, rp;
		BigInteger q, rq;
		BigInteger g, h ;
		BigInteger n, r ;
		BigInteger u = TWO.pow(this.l);
		BigInteger vp, vq, vpvq, tmp;

		while(true)
		{
			//Following the instruction as stated on DGK C++ counterpart
			u = u.nextProbablePrime();
			vp = new BigInteger(this.t, CERTAINTY, this.rnd);//(160, 40, random)
			vq = new BigInteger(this.t, CERTAINTY, this.rnd);//(160, 40, random)
			vpvq = vp.multiply(vq);
			tmp = u.multiply(vp);

			System.out.println("Completed generating vp, vq");

			int needed_bits = this.k/2 - (tmp.bitLength());

			// Generate rp until p is prime such that u * vp divides p-1
			do
			{
				rp = new BigInteger(needed_bits, rnd);
				rp = rp.setBit(needed_bits - 1);
				
				/*
				 * p = rp * u * vp + 1
				 * u | p - 1
				 * vp | p - 1
				 */
				p = rp.multiply(tmp).add(BigInteger.ONE);
			}
			while(!p.isProbablePrime(CERTAINTY));

			tmp = u.multiply(vq);
			needed_bits = this.k/2 - (tmp.bitLength());
			do
			{
				// Same method for q than for p
				rq = new BigInteger(needed_bits, rnd);
				rq = rq.setBit(needed_bits -1);
				q = rq.multiply(tmp).add(BigInteger.ONE); // q = rq*(vq*u) + 1
				//

				/*
				 * q - 1 | rq * vq * u
				 * Therefore,
				 * c^{vp} = g^{vp*m} (mod n) because
				 * rq | (q - 1)
				 */
			}
			while(!q.isProbablePrime(CERTAINTY));
			//Thus we ensure that q is a prime, with p-1 divides the prime numbers vq and u
			if(!NTL.POSMOD(rq, u).equals(BigInteger.ZERO) && 
					!NTL.POSMOD(rp, u).equals(BigInteger.ZERO))
			{
				break;
			}
			
		}
	
		n = p.multiply(q);
		tmp = rp.multiply(rq).multiply(u);
		System.out.println("While Loop 1: n, p and q is generated.");

		while(true)
		{
			//Generate n bit random number
			r = NTL.generateXBitRandom(n.bitLength());	
			h = r.modPow(tmp, n); // h = r^{rp*rq*u} (mod n)

			if (h.equals(BigInteger.ONE))
			{
				continue;
			}

			if (h.modPow(vp,n).equals(BigInteger.ONE))
			{
				continue;//h^{vp}(mod n) = 1
			}

			if (h.modPow(vq,n).equals(BigInteger.ONE))
			{
				continue;//h^{vq}(mod n) = 1
			}

			if (h.modPow(u, n).equals(BigInteger.ONE))
			{
				continue;//h^{u}(mod n) = 1
			}

			if (h.modPow(u.multiply(vq), n).equals(BigInteger.ONE))
			{
				continue;//h^{u*vq} (mod n) = 1
			}

			if (h.modPow(u.multiply(vp), n).equals(BigInteger.ONE))
			{
				continue;//h^{u*vp} (mod n) = 1
			}

			if (h.gcd(n).equals(BigInteger.ONE))
			{
				break;//(h, n) = 1
			}
		}

		BigInteger rprq = rp.multiply(rq);
		System.out.println("While loop 2: h is generated");

		while(true)
		{
			r = NTL.generateXBitRandom(n.bitLength());
			g = r.modPow(rprq, n); //g = r^{rp*rq}(mod n)

			if (g.equals(BigInteger.ONE))
			{
				continue;// g = 1
			}

			if (!g.gcd(n).equals(BigInteger.ONE))
			{
				continue;//(g, n) must be relatively prime
			}
			// h can still be of order u, vp, vq , or a combination of them different that u, vp, vq

			if (g.modPow(u, n).equals(BigInteger.ONE))
			{
				continue;//g^{u} (mod n) = 1
			}

			if (g.modPow(u.multiply(u), n).equals(BigInteger.ONE))
			{
				continue;//g^{u*u} (mod n) = 1
			}

			if (g.modPow(u.multiply(u).multiply(vp), n).equals(BigInteger.ONE))
			{
				continue;//g^{u*u*vp} (mod n) = 1
			}

			if (g.modPow(u.multiply(u).multiply(vq), n).equals(BigInteger.ONE))
			{
				continue;//g^{u*u*vp} (mod n) = 1
			}

			if (g.modPow(vp, n).equals(BigInteger.ONE))
			{
				continue;//g^{vp} (mod n) = 1
			}

			if (g.modPow(vq, n).equals(BigInteger.ONE))
			{
				continue;//g^{vq} (mod n) = 1
			}

			if (g.modPow(u.multiply(vq), n).equals(BigInteger.ONE))
			{
				continue;//g^{u*vq}(mod n) = 1
			}

			if (g.modPow(u.multiply(vp), n).equals(BigInteger.ONE))
			{
				continue;//g^{u*vp} (mod n) = 1
			}

			if (g.modPow(vpvq, n).equals(BigInteger.ONE))
			{
				continue;//g^{vp*vq} (mod n) == 1
			}

			if (NTL.POSMOD(g, p).modPow(vp, p).equals(BigInteger.ONE))
			{
				continue; //g^{vp} (mod p) == 1
			}

			if ((NTL.POSMOD(g,p).modPow(u, p).equals(BigInteger.ONE)))
			{
				continue;//g^{u} (mod p) = 1
			}

			if (NTL.POSMOD(g, q).modPow(vq, q).equals(BigInteger.ONE))
			{
				continue;//g^{vq}(mod q) == 1
			}

			if ((NTL.POSMOD(g, q).modPow(u, q).equals(BigInteger.ONE)))
			{
				continue;//g^{u}(mod q)
			}
			break;
		}
		System.out.println("While loop 3: g is generated");

		System.out.println("Generating hashmaps...");
		pubKey =  new DGKPublicKey(n, g, h, u, this.l, this.t, this.k);
		privkey = new DGKPrivateKey(p, q, vp, vq, pubKey);
		if(no_skip_public_key_maps)
		{
			pubKey.run();
		}
		
		System.out.println("FINISHED WITH DGK KEY GENERATION in " + (System.nanoTime() - start_time)/BILLION + " seconds!");
		return new KeyPair(pubKey, privkey);
	}

	public String toString()
	{
		String s = "";
		s += "l = " + l;
		s += "t = " + t;
		s += "k = " + k;
		return s;
	}
}
