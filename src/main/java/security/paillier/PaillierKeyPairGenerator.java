package security.paillier;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import security.misc.CipherConstants;

public class PaillierKeyPairGenerator extends KeyPairGeneratorSpi implements CipherConstants
{
	private static final Logger logger = LogManager.getLogger(PaillierKeyPairGenerator.class);
	private int key_size = KEY_SIZE;
	private SecureRandom rnd = null;

	// Use this function to generate public and private key
	public static void main(String []  args) {
		String paillier_private_key_file = "paillier";
		String paillier_public_key_file = "paillier.pub";
		KeyPair paillier;
		PaillierPublicKey pk;
		PaillierPrivateKey sk;

		// Create the Key
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		pa.initialize(KEY_SIZE, null);
		paillier = pa.generateKeyPair();
		pk = (PaillierPublicKey) paillier.getPublic();
		sk = (PaillierPrivateKey) paillier.getPrivate();

		// Write the key to a file
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(paillier_public_key_file))) {
			oos.writeObject(pk);
			oos.flush();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(paillier_private_key_file))) {
			oos.writeObject(sk);
			oos.flush();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public void initialize(int key_size, SecureRandom random) 
	{
		this.rnd = random;
		if (key_size % 2 != 0) {
			throw new IllegalArgumentException("Require even number of bits!");
		}
		if (key_size < KEY_SIZE) {
			throw new IllegalArgumentException("Minimum strength of 2048 bits required! Safe until 2030...");
		}
		this.key_size = key_size;
	}

	public KeyPair generateKeyPair() 
	{
		if (this.rnd == null) {
			rnd = new SecureRandom();
		}

		logger.info("Paillier Keys have " + key_size + " bits");
		
		// Chooses a random prime of length k2. The probability that
		// p is not prime is at most 2^(-k2)
		BigInteger p = new BigInteger(key_size/2, CERTAINTY, rnd);
		BigInteger q = new BigInteger(key_size/2, CERTAINTY, rnd);

		BigInteger n = p.multiply(q); // n = pq
		BigInteger modulus = n.multiply(n); // modulus = n^2
		
		// Modifications to the Private key
		BigInteger lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		BigInteger mu = lambda.modInverse(n);
	
		// For signature
		// Build base g \in Z_{n^2} with order n
		BigInteger g = TWO;
		g = find_g(g, lambda, modulus, n);
		
		// Beware of flaw with Paillier if g^{lambda} = 1 (mod n^2)
		while(g.modPow(lambda, modulus).equals(BigInteger.ONE)) {
			g = find_g(g.add(BigInteger.ONE), lambda, modulus, n);
		}

		BigInteger gcd = p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE));
		BigInteger alpha = find_alpha(lambda.divide(gcd));

		PaillierPublicKey pk = new PaillierPublicKey(this.key_size, n, modulus, g);
		PaillierPrivateKey sk = new PaillierPrivateKey(this.key_size, n, modulus, lambda, mu, g, alpha);
		
		logger.info("Completed building Paillier Key Pair!");
		return new KeyPair(pk, sk);
	}

	// Find the smallest divisor!
    // Find alpha
	// alpha | lcm(p - 1, q - 1)
	private static BigInteger find_alpha(BigInteger LCM) {
		BigInteger alpha = TWO;
		while(true) {
			if(LCM.mod(alpha).compareTo(BigInteger.ZERO) == 0) {
				return alpha;
			}
			alpha = alpha.add(BigInteger.ONE);
		}
	}
	
	// Build generator
	private static BigInteger find_g(BigInteger g, BigInteger lambda, BigInteger modulus, BigInteger n) {
		while(true)
		{
			if(PaillierCipher.L(g.modPow(lambda, modulus), n).gcd(n).equals(BigInteger.ONE)) {
				return g;		
			}
			g = g.add(BigInteger.ONE);
		}
	}
}
