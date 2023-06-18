package security.gm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

import security.misc.CipherConstants;
import security.misc.NTL;

public class GMKeyPairGenerator extends KeyPairGeneratorSpi implements CipherConstants
{
	int key_size;

	// https://medium.com/coinmonks/probabilistic-encryption-using-the-goldwasser-micali-gm-method-7f9893a93ac9
	public void initialize(int key_size, SecureRandom random) {
		this.key_size = key_size;
	}

	public KeyPair generateKeyPair() {
		BigInteger p = new BigInteger(key_size/2, CERTAINTY, rnd);
		BigInteger q = new BigInteger(key_size/2, CERTAINTY, rnd);
		// y is a quadratic non-residue modulo n
		BigInteger y = NTL.quadratic_non_residue(p, q);
		BigInteger n = p.multiply(q);
		return new KeyPair(new GMPublicKey(n, y), new GMPrivateKey(p, q));
	}
}
