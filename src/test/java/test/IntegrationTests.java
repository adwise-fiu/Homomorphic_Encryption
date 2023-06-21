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

import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class IntegrationTests implements constants
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
		pg.initialize(KEY_SIZE, null);
		el_gamal = pg.generateKeyPair();
	}

	// Test Basic Implementation of Alice and Bob
	@Test
	public void integration_test() throws IOException, InterruptedException, ClassNotFoundException {
		bob bob_version_one = new bob(paillier, dgk, el_gamal);
		Thread andrew = new Thread(new test_bob(bob_version_one, 9200));
		andrew.start();

		// Wait then connect!
		System.out.println("Sleep to give bob time to make keys...");
		Thread.sleep(2 * 1000);
		System.out.println("Alice starting...");

		alice Niu = new alice(new Socket("127.0.0.1", 9200));
		Niu.receivePublicKeys();

		Thread yujia = new Thread(new test_alice(Niu, paillier, dgk));
		yujia.start();
		try {
			andrew.join();
			yujia.join();
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	// Test Veugen implementation of Alice and Bob
	@Test
	public void veugen_integration_test() throws IOException, InterruptedException, ClassNotFoundException {

		bob_veugen bob_version_two = new bob_veugen(paillier, dgk, el_gamal);
		Thread andrew = new Thread(new test_bob(bob_version_two, 9201));
		andrew.start();

		// Wait then connect!
		System.out.println("Sleep to give bob time to make keys...");
		Thread.sleep(2 * 1000);
		System.out.println("Alice starting...");

		alice Niu = new alice_veugen(new Socket("127.0.0.1", 9201));
		Niu.receivePublicKeys();

		Thread yujia = new Thread(new test_alice(Niu, paillier, dgk));
		yujia.start();
		try {
			andrew.join();
			yujia.join();
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	// Test El Gamal version of Alice and Bob
	@Test
	public void el_gamal_integration_test() throws IOException, InterruptedException, ClassNotFoundException {
		bob_veugen bob_version_two = new bob_veugen(paillier, dgk, el_gamal);
		Thread andrew = new Thread(new test_el_gamal_bob(bob_version_two, 9202));
		andrew.start();

		// Wait then connect!
		System.out.println("Sleep to give bob time to make keys...");
		Thread.sleep(2 * 1000);
		System.out.println("Alice starting...");

		alice_veugen Niu = new alice_veugen(new Socket("127.0.0.1", 9202));
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

	// Test Joye and Salehi Implementation of Alice and Bob
	/*
	@Test
	public void joye_integration_test() throws IOException, InterruptedException, ClassNotFoundException {

		bob_joye bob_version_three = new bob_joye(paillier, dgk, el_gamal);
		Thread andrew = new Thread(new test_bob(bob_version_three, 9203));
		andrew.start();

		// Wait then connect!
		System.out.println("Sleep to give bob time to make keys...");
		Thread.sleep(2 * 1000);
		System.out.println("Alice starting...");

		alice Niu = new alice_joye(new Socket("127.0.0.1", 9203));
		Niu.receivePublicKeys();

		Thread yujia = new Thread(new test_alice(Niu, paillier, dgk));
		yujia.start();
		try {
			andrew.join();
			yujia.join();
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	 */
}
