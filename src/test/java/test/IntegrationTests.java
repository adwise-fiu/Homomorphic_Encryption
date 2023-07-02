package test;

import security.elgamal.ElGamalPrivateKey;
import security.paillier.PaillierKeyPairGenerator;
import security.dgk.DGKKeyPairGenerator;
import security.elgamal.ElGamalKeyPairGenerator;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;

import org.junit.BeforeClass;
import org.junit.Test;
import security.socialistmillionaire.*;

public class IntegrationTests implements constants
{
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

		for (int i = 0; i < test_set.length; i++) {
			test_set[i] = test_set[i].add(FIVE);
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

		for (int i = 0; i < test_set.length; i++) {
			test_set[i] = test_set[i].add(BigInteger.TEN);
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
		ElGamalKeyPairGenerator pg = new ElGamalKeyPairGenerator(true);
		pg.initialize(EL_GAMAL_KEY_SIZE, null);
		el_gamal = pg.generateKeyPair();
	}

	@Test
	public void all_integration_test() throws IOException, InterruptedException, ClassNotFoundException {
		bob [] all_bobs = { new bob(paillier, dgk, el_gamal), new bob_veugen(paillier, dgk, el_gamal)};
		alice [] all_alice = { new alice(), new alice_veugen() };

		for (int i = 0; i < all_bobs.length; i++) {
			Thread andrew = new Thread(new test_bob(all_bobs[i], 9200 + i));
			andrew.start();

			// Wait then connect!
			System.out.println("Sleep to give bob time to make keys...");
			Thread.sleep(2 * 1000);
			System.out.println("Alice starting...");

			all_alice[i].set_socket(new Socket("127.0.0.1", 9200 + i));
			all_alice[i].receivePublicKeys();

			Thread yujia = new Thread(new test_alice(all_alice[i], paillier, dgk));
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


	// Test El Gamal version of Alice and Bob
	@Test
	public void el_gamal_integration_test() throws IOException, InterruptedException, ClassNotFoundException {
		bob_elgamal bob_version_two = new bob_elgamal(paillier, dgk, el_gamal);
		Thread andrew = new Thread(new test_el_gamal_bob(bob_version_two, 10000));
		andrew.start();

		// Wait then connect!
		System.out.println("Sleep to give bob time to make keys...");
		Thread.sleep(2 * 1000);
		System.out.println("Alice starting...");

		alice_elgamal Niu = new alice_elgamal();
		Niu.set_socket(new Socket("127.0.0.1", 10000));
		Niu.receivePublicKeys();

		Thread yujia = new Thread(new test_el_gamal_alice(Niu, (ElGamalPrivateKey) el_gamal.getPrivate()));
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
