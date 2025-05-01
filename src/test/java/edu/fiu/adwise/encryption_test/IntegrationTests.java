/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.encryption_test;

import edu.fiu.adwise.homomorphic_encryption.dgk.DGKOperations;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKPrivateKey;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKPublicKey;
import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamalPrivateKey;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierKeyPairGenerator;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKKeyPairGenerator;
import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamalKeyPairGenerator;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.util.List;

import edu.fiu.adwise.homomorphic_encryption.socialistmillionaire.*;
import org.junit.BeforeClass;
import org.junit.Test;
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

		int [] y_bits = { 3, 16, 7};

        for (int yBit : y_bits) {
			// Works both when y and x is hard coded to be 10 bits long.
			x = NTL.generateXBitRandom(yBit);
			y = NTL.generateXBitRandom(7);
			encrypted_bits = andrew.encrypt_bits(y);

            logger.debug("x in bits looks like {} and value is {}", x.toString(2), x);
            logger.debug("y in bits looks like {} and value is {}", y.toString(2), y);

			xor = Niu.encrypted_xor(x, encrypted_bits);
            // Few things to note, xor can be smaller that inputs.
            // Prints top to bottom, matches left to right when printing bit string.
            // If x and y same bit-size, IT WORKS
            // As expected, right now it IS WRONG, if x is smaller in bits, let's fix this first.
            StringBuilder collect_bits = new StringBuilder();
            for (int i = 0; i < xor.length; i++) {
                long l = DGKOperations.decrypt(xor[i], (DGKPrivateKey) dgk.getPrivate());
                logger.debug("i={} is {}", i, l);
                collect_bits.append(l);
            }
            expected_xor = x.xor(y);
            logger.debug("xor regular: {}", expected_xor.toString(2));
            assertEquals(new BigInteger(collect_bits.toString(), 2), x.xor(y));
        }
	}

	@Test
	public void test_debug_joye_protocol_one() throws HomomorphicException {
		List<Integer> set_l;
		BigInteger [] C;
		int delta_b;
		alice_joye Niu = new alice_joye();
		bob andrew = new bob(paillier, dgk);
		Niu.setDGKMode(true);
		andrew.setDGKMode(true);
		Niu.setDGKPublicKey((DGKPublicKey) dgk.getPublic());
		Niu.set_dgk_private_key((DGKPrivateKey) dgk.getPrivate());

		BigInteger x;
		BigInteger y;
		BigInteger [] encrypted_bits;
		BigInteger[] xor;
		int [] y_bits = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

		for (int yBit : y_bits) {
			// Works both when y and x is hard coded to be 10 bits long.
			x = NTL.generateXBitRandom(yBit);
			y = NTL.generateXBitRandom(10);
			encrypted_bits = andrew.encrypt_bits(y);
			xor = Niu.encrypted_xor(x, encrypted_bits);

			logger.debug("x in bits looks like {} and value is {}", x.toString(2), x);
			logger.debug("y in bits looks like {} and value is {}", y.toString(2), y);

			// This is beyond XOR, and the bug
			int delta_a = alice_joye.compute_delta_a(x, xor.length);
			set_l = Niu.form_set_l(x, delta_a, xor);
			C = Niu.compute_c(x, encrypted_bits, xor, delta_a, set_l);
			delta_b = andrew.compute_delta_b(C);

			if (x.compareTo(y) <= 0) {
				assertEquals(1, delta_a ^ delta_b);
			} else {
				assertEquals(0, delta_a ^ delta_b);
			}
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
            logger.info("Sleep to give {} time to make keys...", all_bobs[i].getClass().getName());
			Thread.sleep(2 * 1000);
            logger.info("{} is starting...", all_alice[i].getClass().getName());

			all_alice[i].set_socket(new Socket("127.0.0.1", 9200 + i));
			all_alice[i].receivePublicKeys();

			Thread yujia = new Thread(new test_alice(all_alice[i], paillier, dgk));
			yujia.start();

			andrew.join();
			yujia.join();


			logger.info("Bob wrote {} bytes to the socket", all_bobs[i].get_bytes_sent());
			logger.info("Alice wrote {} bytes to the socket", all_alice[i].get_bytes_sent());
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

		andrew.join();
		yujia.join();

        logger.info("El Gamal bob wrote {} bytes to the socket", bob_version_two.get_bytes_sent());
		logger.info("El Gamal alice wrote {} bytes to the socket", Niu.get_bytes_sent());
	}
}
