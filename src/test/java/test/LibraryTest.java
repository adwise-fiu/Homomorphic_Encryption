package test;

import security.gm.GMCipher;
import security.gm.GMKeyPairGenerator;
import security.gm.GMPrivateKey;
import security.gm.GMPublicKey;
import security.misc.HomomorphicException;

import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;
import security.paillier.PaillierSignature;
import security.dgk.DGKOperations;
import security.dgk.DGKKeyPairGenerator;
import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalKeyPairGenerator;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamalSignature;
import security.elgamal.ElGamal_Ciphertext;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.*;

public class LibraryTest
{	
	private static final int KEY_SIZE = 1024;
	
	// All Key Pairs
	private static KeyPair dgk = null;
	private static KeyPair paillier = null;
	private static KeyPair el_gamal = null;

	public static BigInteger [] generate_low() {
		BigInteger [] test_set = new BigInteger[16];
		test_set[0] = new BigInteger("1");
		test_set[1] = new BigInteger("2");
		test_set[2] = new BigInteger("4");
		test_set[3] = new BigInteger("8");
		test_set[4] = new BigInteger("16");
		test_set[5] = new BigInteger("32");
		test_set[6] = new BigInteger("64");
		test_set[7] = new BigInteger("128");
		test_set[8] = new BigInteger("256");
		test_set[9] = new BigInteger("512");

		test_set[10] = new BigInteger("1024");
		test_set[11] = new BigInteger("2048");
		test_set[12] = new BigInteger("4096");
		test_set[13] = new BigInteger("8192");
		test_set[14] = new BigInteger("16384");
		test_set[15] = new BigInteger("32768");

		BigInteger t = BigInteger.ZERO;
		for (int i = 0; i < test_set.length;i++) {
			test_set[i] = test_set[i].add(t);
		}
		return test_set;
	}

	public static BigInteger[] generate_mid() {
		BigInteger [] test_set = new BigInteger[16];
		test_set[0] = new BigInteger("1");
		test_set[1] = new BigInteger("2");
		test_set[2] = new BigInteger("4");
		test_set[3] = new BigInteger("8");
		test_set[4] = new BigInteger("16");
		test_set[5] = new BigInteger("32");
		test_set[6] = new BigInteger("64");
		test_set[7] = new BigInteger("128");
		test_set[8] = new BigInteger("256");
		test_set[9] = new BigInteger("512");

		test_set[10] = new BigInteger("1024");
		test_set[11] = new BigInteger("2048");
		test_set[12] = new BigInteger("4096");
		test_set[13] = new BigInteger("8192");
		test_set[14] = new BigInteger("16384");
		test_set[15] = new BigInteger("32768");

		BigInteger t = new BigInteger("5");
		for (int i = 0; i < test_set.length; i++) {
			test_set[i] = test_set[i].add(t);
		}
		return test_set;
	}

	public static BigInteger[] generate_high() {
		BigInteger [] test_set = new BigInteger[16];

		test_set[0] = new BigInteger("1");
		test_set[1] = new BigInteger("2");
		test_set[2] = new BigInteger("4");
		test_set[3] = new BigInteger("8");
		test_set[4] = new BigInteger("16");
		test_set[5] = new BigInteger("32");
		test_set[6] = new BigInteger("64");
		test_set[7] = new BigInteger("128");
		test_set[8] = new BigInteger("256");
		test_set[9] = new BigInteger("512");

		test_set[10] = new BigInteger("1024");
		test_set[11] = new BigInteger("2048");
		test_set[12] = new BigInteger("4096");
		test_set[13] = new BigInteger("8192");
		test_set[14] = new BigInteger("16384");
		test_set[15] = new BigInteger("32768");

		BigInteger t = new BigInteger("10");
		for (int i = 0; i < test_set.length; i++) {
			test_set[i] = test_set[i].add(t);
		}
		return test_set;
	}

	@BeforeClass
	public static void generate_keys() {
		// Build DGK Keys
		DGKKeyPairGenerator p = new DGKKeyPairGenerator();
		p.initialize(KEY_SIZE, null);
		dgk = p.generateKeyPair();

		// Build Paillier Keys
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		pa.initialize(KEY_SIZE, null);
		paillier = pa.generateKeyPair();		

		
		// Build Additive El-Gamal Key
		ElGamalKeyPairGenerator pg = new ElGamalKeyPairGenerator();
		// NULL -> ADDITIVE
		// NOT NULL -> MULTIPLICATIVE
		pg.initialize(KEY_SIZE, null);
		el_gamal = pg.generateKeyPair();

		// Build Goldwasser-Micali Keys
		GMKeyPairGenerator gm_gen = new GMKeyPairGenerator();
		gm_gen.initialize(KEY_SIZE, null);
		KeyPair gm_key_pair = gm_gen.generateKeyPair();
	}

	@Test
	public void integration_test() {
		Thread andrew = new Thread(new Bob(paillier, dgk, el_gamal));
		andrew.start();
		Thread yujia = new Thread(new Alice());
		yujia.start();
		try {
			andrew.join();
			yujia.join();
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
