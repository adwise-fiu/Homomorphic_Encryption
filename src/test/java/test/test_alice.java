package test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;

import security.dgk.DGKOperations;
import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;
import security.socialistmillionaire.alice;

import static org.junit.Assert.*;

public class test_alice implements Runnable, constants
{
	public test_alice(alice Niu, KeyPair paillier, KeyPair dgk) {
		this.Niu = Niu;
		if (paillier.getPrivate() instanceof PaillierPrivateKey) {
			this.paillier_private = (PaillierPrivateKey) paillier.getPrivate();
		}
		if (dgk.getPrivate() instanceof DGKPrivateKey) {
			this.dgk_private = (DGKPrivateKey) dgk.getPrivate();
		}
	}

	private final alice Niu;
	private static PaillierPublicKey paillier_public;
	private static DGKPublicKey dgk_public_key;

	private PaillierPrivateKey paillier_private;
	private DGKPrivateKey dgk_private;
	
	// Get your test data...
	private static final BigInteger [] low = IntegrationTests.generate_low();
	private static final BigInteger [] mid = IntegrationTests.generate_mid();
	private static final BigInteger [] high = IntegrationTests.generate_high();
	
	// This would have been in Alice's (Client) Main Function
	public void run() {
		try {
			paillier_public = Niu.getPaillierPublicKey();
			dgk_public_key = Niu.getDGKPublicKey();

			test_outsourced_multiply(true);
			test_outsourced_multiply(false);

			test_outsourced_division(true);
			test_outsourced_division(false);

			test_protocol_one(true);
			test_protocol_one(false);

			test_sorting(true);
			test_sorting(false);

			test_protocol_two(true);
			test_protocol_two(false);
		}
		catch (ClassNotFoundException | IOException | HomomorphicException e) {
			e.printStackTrace();
		}
	}
	
	public void test_sorting(boolean dgk_mode)
			throws ClassNotFoundException, IOException, HomomorphicException {
		System.out.println("Alice: Testing Sorting with DGK Mode: " + dgk_mode);
		BigInteger [] toSort = new BigInteger[low.length];
		Niu.setDGKMode(dgk_mode);
		for(int i = 0; i < low.length; i++) {
			toSort[i] = NTL.generateXBitRandom(5);
			if (dgk_mode) {
				toSort[i] = DGKOperations.encrypt(toSort[i], dgk_public_key);
			}
			else {
				toSort[i] = PaillierCipher.encrypt(toSort[i], paillier_public);
			}
		}

		if (Niu.getClass() == security.socialistmillionaire.alice.class) {
			// Protocol 2 won't work on regular alice
			return;
		}
		Niu.getKMin(toSort, 3);
		for (int i = 0; i < toSort.length; i++) {
			if (dgk_mode) {
				toSort[i] = BigInteger.valueOf(DGKOperations.decrypt(toSort[i], dgk_private));
			}
			else {
				toSort[i] = PaillierCipher.decrypt(toSort[i], paillier_private);
			}
		}
		System.out.println("Sorted and moved 3 lowest values: " + Arrays.toString(toSort));
	}

	public void test_outsourced_multiply(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
		Niu.setDGKMode(dgk_mode);
		BigInteger temp;
		System.out.println("Alice: Testing Multiplication with DGK Mode: " + dgk_mode);
		if(dgk_mode) {
			temp = Niu.multiplication(DGKOperations.encrypt(THOUSAND, dgk_public_key),
					DGKOperations.encrypt(TWO, dgk_public_key));
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 2000);

			temp = Niu.multiplication(DGKOperations.encrypt(THOUSAND, dgk_public_key),
					DGKOperations.encrypt(THREE, dgk_public_key));
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 3000);

			temp = Niu.multiplication(DGKOperations.encrypt(THOUSAND, dgk_public_key),
					DGKOperations.encrypt(FIVE, dgk_public_key));
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 5000);
		}
		else {
			temp = Niu.multiplication(PaillierCipher.encrypt(THOUSAND, paillier_public),
					PaillierCipher.encrypt(TWO, paillier_public));
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), TWO_THOUSAND);

			temp = Niu.multiplication(PaillierCipher.encrypt(THOUSAND, paillier_public),
					PaillierCipher.encrypt(THREE, paillier_public));
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), THREE_THOUSAND);

			temp = Niu.multiplication(PaillierCipher.encrypt(THOUSAND, paillier_public),
					PaillierCipher.encrypt(FIFTY, paillier_public));
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), FIFTY_THOUSAND);
		}
	}

	public void test_outsourced_division(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
		// Division Test, Paillier
		// REMEMBER THE OUTPUT IS THE ENCRYPTED ANSWER, ONLY BOB CAN VERIFY THE ANSWER
		Niu.setDGKMode(dgk_mode);
		System.out.println("Alice: Division Tests, DGK Mode: " + dgk_mode);
		BigInteger d;
		BigInteger temp;
		if (dgk_mode) {
			d = DGKOperations.encrypt(100, dgk_public_key);
		}
		else {
			d = PaillierCipher.encrypt(100, paillier_public);
		}
		temp = Niu.division(d, 2);//100/2 = 50
		if (dgk_mode) {
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 50);
		}
		else {
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), FIFTY);
		}
		temp = Niu.division(d, 3);//100/3 = 33
		if (dgk_mode) {
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 33);
		}
		else {
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), THIRTY_THREE);
		}
		temp = Niu.division(d, 4);//100/4 = 25
		if (dgk_mode) {
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 25);
		}
		else {
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), TWENTY_FIVE);
		}
		temp = Niu.division(d, 5);//100/5 = 20
		if (dgk_mode) {
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 20);
		}
		else {
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), TWENTY);
		}
		temp = Niu.division(d, 25);//100/25 = 4
		if (dgk_mode) {
			assertEquals(DGKOperations.decrypt(temp, dgk_private), 4);
		}
		else {
			assertEquals(PaillierCipher.decrypt(temp, paillier_private), FOUR);
		}
	}

	public void test_protocol_one(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
		System.out.println("Alice: Testing Protocol 1 with DGK Mode: " + dgk_mode);
		boolean answer;
		Niu.setDGKMode(dgk_mode);

		// Bob always will compare with a medium
		for(BigInteger l: low) {
			// X <= Y is true
			answer = Niu.Protocol1(l);
			assertTrue(answer);
		}
		for(BigInteger l: mid) {
			// X <= Y is true
			answer = Niu.Protocol1(l);
			assertTrue(answer);
		}
		for(BigInteger l: high) {
			// X <= Y is false
			answer = Niu.Protocol1(l);
			assertFalse(answer);
		}
	}

	// X >= Y is checked
	public void test_protocol_two(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
		System.out.println("Alice: Testing Protocol 2 with DGK Mode: " + dgk_mode);

		Niu.setDGKMode(dgk_mode);
		boolean answer;
		if (!(dgk_mode && Niu.getClass() == security.socialistmillionaire.alice.class)) {
			for (int i = 0; i < low.length;i++) {
				// X >= Y is false
				answer = Niu.Protocol2(PaillierCipher.encrypt(low[i], paillier_public),
						PaillierCipher.encrypt(mid[i], paillier_public));
				assertFalse(answer);

				// X >= Y is true
				answer = Niu.Protocol2(PaillierCipher.encrypt(mid[i], paillier_public),
						PaillierCipher.encrypt(mid[i], paillier_public));
				assertTrue(answer);

				// X >= Y is true
				answer = Niu.Protocol2(PaillierCipher.encrypt(high[i], paillier_public),
						PaillierCipher.encrypt(mid[i], paillier_public));
				assertTrue(answer);
			}
		}
	}
}
