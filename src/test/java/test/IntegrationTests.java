package test;

import security.dgk.DGKOperations;
import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.elgamal.ElGamalPrivateKey;
import security.misc.HomomorphicException;
import security.misc.NTL;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static org.junit.Assert.assertEquals;

public class IntegrationTests implements constants
{
	private static final Logger logger = LogManager.getLogger(IntegrationTests.class);
	// All Key Pairs
	private static KeyPair dgk = null;
	private static KeyPair paillier = null;
	private static KeyPair el_gamal = null;

	public static BigInteger [] generate_values(BigInteger offset) {
		BigInteger [] test_set = new BigInteger[16];
		for (int i = 0; i < test_set.length; i++) {
			test_set[i] = TWO.pow(i);
			test_set[i] = test_set[i].add(offset);
		}
		return test_set;
	}

	public static BigInteger [] generate_low() {
		return generate_values(BigInteger.ZERO);
	}

	public static BigInteger[] generate_mid() {
		return generate_values(FIVE);
	}

	public static BigInteger[] generate_high() {
		return generate_values(BigInteger.TEN);
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
	public void test_encrypted_xor() throws HomomorphicException {
		alice Niu = new alice();
		bob andrew = new bob(paillier, dgk);
		Niu.setDGKMode(true);
		andrew.setDGKMode(true);
		Niu.setDGKPublicKey((DGKPublicKey) dgk.getPublic());
		Niu.set_dgk_private_key((DGKPrivateKey) dgk.getPrivate());

		BigInteger [] encrypted_bits;
		BigInteger x;
		BigInteger y;
		BigInteger [] xor;
		BigInteger expected_xor;

		int [] y_bits = { 10, 15, 5};

        for (int yBit : y_bits) {
			// Works both when y and x is hard coded to be 10 bits long.
			x = NTL.generateXBitRandom(yBit);
			y = NTL.generateXBitRandom(10);
			encrypted_bits = andrew.encrypt_bits(y);

            logger.debug("x in bits looks like " + x.toString(2) + " and vale is " + x);
            logger.debug("y in bits looks like " + y.toString(2) + " and vale is " + y);

			xor = Niu.encrypted_xor(x, encrypted_bits);
            // Few things to note, xor can be smaller that inputs.
            // Prints top to bottom, matches left to right when printing bit string.
            // If x and y same bit-size, IT WORKS
            // As expected, right now it IS WRONG, if x is smaller in bits, let's fix this first.
            StringBuilder collect_bits = new StringBuilder();
            for (int i = 0; i < xor.length; i++) {
                long l = DGKOperations.decrypt(xor[i], (DGKPrivateKey) dgk.getPrivate());
                logger.debug("i=" + i + " is " + l);
                collect_bits.append(l);
            }
            expected_xor = x.xor(y);
            logger.debug("xor regular: " + expected_xor.toString(2));
            assertEquals(new BigInteger(collect_bits.toString(), 2), x.xor(y));
        }
	}

	@Test
	public void all_integration_test() throws IOException, InterruptedException, ClassNotFoundException {
		bob [] all_bobs = {
				new bob(paillier, dgk, el_gamal),
				new bob_veugen(paillier, dgk, el_gamal),
				new bob_joye(paillier, dgk, el_gamal)
		};
		alice [] all_alice = {
				new alice(),
				new alice_veugen(),
				new alice_joye()
		};

		for (int i = 0; i < all_bobs.length; i++) {
			Thread andrew = new Thread(new test_bob(all_bobs[i], 9200 + i));
			andrew.start();

			// Wait then connect!
			logger.info("Sleep to give " + all_bobs[i].getClass().getName() + " time to make keys...");
			Thread.sleep(2 * 1000);
			logger.info(all_alice[i].getClass().getName() + " is starting...");

			all_alice[i].set_socket(new Socket("127.0.0.1", 9200 + i));
			all_alice[i].receivePublicKeys();

			Thread yujia = new Thread(new test_alice(all_alice[i], paillier, dgk));
			yujia.start();
			try {
				andrew.join();
				yujia.join();
			}
			catch (InterruptedException e) {
				logger.error(e.getStackTrace());
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
		logger.info("Sleep to give bob time to make keys...");
		Thread.sleep(2 * 1000);
		logger.info("Alice starting...");

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
			logger.error(e.getStackTrace());
		}
	}
}
