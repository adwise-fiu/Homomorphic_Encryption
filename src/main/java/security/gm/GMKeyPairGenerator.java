package security.gm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

import security.misc.CipherConstants;
import security.misc.NTL;

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
		// y is a quadratic nonresidue modulo n
		BigInteger y = NTL.quadratic_non_residue(p, q);
		BigInteger n = p.multiply(q);
		return new KeyPair(new GMPublicKey(n, y), new GMPrivateKey(p, q));
	}
}
