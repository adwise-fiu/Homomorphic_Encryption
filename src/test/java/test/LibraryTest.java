package test;

import security.gm.GMCipher;
import security.gm.GMKeyPairGenerator;
import security.gm.GMPrivateKey;
import security.gm.GMPublicKey;
import security.misc.HomomorphicException;

import security.paillier.PaillierCipher;
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
	
	// Build DGK Keys
	private static DGKPublicKey dgk_pk = null;
	private static DGKPrivateKey dgk_sk = null;
	
	private static PaillierPublicKey pk = null;
	private static PaillierPrivateKey sk = null;

	private static ElGamalPublicKey el_pk = null;
	private static ElGamalPrivateKey el_sk = null;

	private static GMPrivateKey gm_sk;
	private static GMPublicKey gm_pk;

	public static BigInteger [] generate_low()
	{
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
		for (int i = 0; i < test_set.length;i++)
		{
			test_set[i] = test_set[i].add(t);
		}
		return test_set;
	}

	public static BigInteger[] generate_mid()
	{
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
		for (int i = 0; i < test_set.length; i++)
		{
			test_set[i] = test_set[i].add(t);
		}
		return test_set;
	}

	public static BigInteger[] generate_high()
	{
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
		for (int i = 0; i < test_set.length; i++)
		{
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
		
		dgk_pk = (DGKPublicKey) dgk.getPublic();
		dgk_sk = (DGKPrivateKey) dgk.getPrivate();
		
		// Build Paillier Keys
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		pa.initialize(KEY_SIZE, null);
		paillier = pa.generateKeyPair();		
		pk = (PaillierPublicKey) paillier.getPublic();
		sk = (PaillierPrivateKey) paillier.getPrivate();
		
		// Build Additive El-Gamal Key
		ElGamalKeyPairGenerator pg = new ElGamalKeyPairGenerator();
		// NULL -> ADDITIVE
		// NOT NULL -> MULTIPLICATIVE
		pg.initialize(KEY_SIZE, null);
		el_gamal = pg.generateKeyPair();
		el_pk = (ElGamalPublicKey) el_gamal.getPublic();
		el_sk = (ElGamalPrivateKey) el_gamal.getPrivate();

		// Build Goldwasser-Micali Keys
		GMKeyPairGenerator gm_gen = new GMKeyPairGenerator();
		gm_gen.initialize(KEY_SIZE, null);
		KeyPair gm_key_pair = gm_gen.generateKeyPair();

		gm_pk = (GMPublicKey) gm_key_pair.getPublic();
		gm_sk = (GMPrivateKey) gm_key_pair.getPrivate();
	}
	
	@Test
	public void basic_DGK() throws HomomorphicException {
		// Test D(E(X)) = X
		BigInteger a = DGKOperations.encrypt(BigInteger.TEN, dgk_pk);
		a = BigInteger.valueOf(DGKOperations.decrypt(a, dgk_sk));
		assertEquals(BigInteger.TEN, a);
		
		// Test Addition, note decrypting returns a long not BigInteger
		a = DGKOperations.encrypt(a, dgk_pk);
		a = DGKOperations.add(a, a, dgk_pk); //20
		assertEquals(20, DGKOperations.decrypt(a, dgk_sk));
		
		// Test Subtraction, note decrypting returns a long not BigInteger
		a = DGKOperations.subtract(a, DGKOperations.encrypt(BigInteger.TEN, dgk_pk), dgk_pk);// 20 - 10
		assertEquals(10, DGKOperations.decrypt(a, dgk_sk));
		
		// Test Multiplication, note decrypting returns a long not BigInteger
		a = DGKOperations.multiply(a, BigInteger.TEN, dgk_pk); // 10 * 10
		assertEquals(100, DGKOperations.decrypt(a, dgk_sk));
		
		// Test Division, Division is failing for some reason...?
		a = DGKOperations.divide(a, new BigInteger("2"), dgk_pk); // 100/2
		assertEquals(50, DGKOperations.decrypt(a, dgk_sk));
	}
	
	@Test
	public void basic_Paillier() throws HomomorphicException {	
		// Test D(E(X)) = X
		BigInteger a;
		a = PaillierCipher.decrypt(PaillierCipher.encrypt(BigInteger.TEN, pk), sk);
		assertEquals(BigInteger.TEN, a);
		
		// Test Addition
		a = PaillierCipher.encrypt(BigInteger.TEN, pk);
		a = PaillierCipher.add(a, a, pk); // 20
		assertEquals(new BigInteger("20"), PaillierCipher.decrypt(a, sk));

		// Test addition, cipher-text and plain-text (skip encryption)
		a = PaillierCipher.encrypt(BigInteger.TEN, pk);
		a = PaillierCipher.add_plaintext(a, BigInteger.TEN, pk);
		assertEquals(new BigInteger("20"), PaillierCipher.decrypt(a, sk));
		
		// Test Subtraction
		a = PaillierCipher.subtract(PaillierCipher.encrypt(new BigInteger("20"), pk),
				PaillierCipher.encrypt(BigInteger.TEN, pk), pk);// 20 - 10
		assertEquals(BigInteger.TEN, PaillierCipher.decrypt(a, sk));

		// Test Subtraction plaintext
		/*
		a = PaillierCipher.subtract_plaintext(PaillierCipher.encrypt(new BigInteger("20"), pk),
				BigInteger.TEN, pk);// 20 - 10
		assertEquals(BigInteger.TEN, PaillierCipher.decrypt(a, sk));
		*/

		// Test Multiplication
		a = PaillierCipher.multiply(PaillierCipher.encrypt(BigInteger.TEN, pk),
				BigInteger.TEN, pk); // 10 * 10
		assertEquals(new BigInteger("100"), PaillierCipher.decrypt(a, sk));
		
		// Test Division
		a = PaillierCipher.divide(PaillierCipher.encrypt(new BigInteger("100"), pk),
				new BigInteger("2"), pk); // 100/2
		assertEquals(new BigInteger("50"), PaillierCipher.decrypt(a, sk));
	}
	
	// NOTE: THIS IS THE MULTIPLICATIVE VERSION
	@Test
	public void basic_ElGamal_multiply() {
		// Build DGK Keys
		ElGamalKeyPairGenerator p = new ElGamalKeyPairGenerator();
		p.initialize(1024, new SecureRandom());
		KeyPair pe = p.generateKeyPair();
		
		ElGamalPublicKey pk = (ElGamalPublicKey) pe.getPublic();
		ElGamalPrivateKey sk = (ElGamalPrivateKey) pe.getPrivate();
		
		// Test D(E(X)) = X
		ElGamal_Ciphertext a = ElGamalCipher.encrypt(BigInteger.TEN, pk);
		BigInteger alpha = ElGamalCipher.decrypt(a, sk);
		assertEquals(BigInteger.TEN, alpha);
		
		// Test Multiplication
		// Can multiply two cipher-texts and store product of ciphers
		a = ElGamalCipher.multiply(a, ElGamalCipher.encrypt(BigInteger.TEN, pk), pk); // 10 * 10
		assertEquals(new BigInteger("100"), ElGamalCipher.decrypt(a, sk));
		
		// Test Division
		a = ElGamalCipher.divide(a, ElGamalCipher.encrypt(new BigInteger("2"), pk), pk); // 100/2 
		assertEquals(new BigInteger("50"), ElGamalCipher.decrypt(a, sk));
	}
	
	// NOTE: THIS IS THE ADDITIVE VERSION
	@Test
	public void basic_ElGamal_add() {
		// Test D(E(X)) = X
		ElGamal_Ciphertext a = ElGamalCipher.encrypt(BigInteger.TEN, el_pk);
		BigInteger alpha = ElGamalCipher.decrypt(a, el_sk);
		assertEquals(BigInteger.TEN, alpha);
		
		// Test Addition
		a = ElGamalCipher.encrypt(BigInteger.TEN, el_pk);
		a = ElGamalCipher.add(a, a, el_pk); //20
		assertEquals(new BigInteger("20"), ElGamalCipher.decrypt(a, el_sk));
		
		// Test Subtraction
		a = ElGamalCipher.subtract(a, ElGamalCipher.encrypt(BigInteger.TEN, el_pk), el_pk);// 20 - 10
		assertEquals(BigInteger.TEN, ElGamalCipher.decrypt(a, el_sk));
		
		// Test Multiplication
		a = ElGamalCipher.multiply_scalar(a, BigInteger.TEN, el_pk); // 10 * 10
		assertEquals(new BigInteger("100"), ElGamalCipher.decrypt(a, el_sk));
		
		// Test Division - INVALID FOR ADDITIVE MODE
	}

	@Test
	public void basic_gm() throws HomomorphicException {
		// Test D(E(X)) = X
		List<BigInteger> a = GMCipher.encrypt(BigInteger.TEN, gm_pk);
		assertEquals(BigInteger.TEN, GMCipher.decrypt(a, gm_sk));

		// Test XOR
		BigInteger [] c = GMCipher.xor(a, a, gm_pk);
		assertEquals(BigInteger.ZERO, GMCipher.decrypt(c, gm_sk));
	}

	@Test
	public void paillier_test_product_sum(){
		// sum

		// sum_product
	}

	@Test
	public void paillier_signature() {

		// Paillier Signature
		List<BigInteger> signed_answer = PaillierSignature.sign(BigInteger.valueOf(42), sk);

		// Test signatures
		for (int i = 0; i < 1000; i++) {
			boolean answer = PaillierSignature.verify(BigInteger.valueOf(i), signed_answer, pk);
			if (i == 42) {
				assertTrue(answer);
			}
			else {
				assertFalse(answer);
			}
		}
	}

	@Test
	public void el_gamal_signature() {
		// ElGamal Signature
		ElGamal_Ciphertext signed = ElGamalSignature.sign(new BigInteger("42"), el_sk);

		for (int i = 0; i < 1000; i++) {
			boolean answer = ElGamalSignature.verify(BigInteger.valueOf(i), signed, el_pk);
			if (i == 42) {
				assertTrue(answer);
			}
			else {
				assertFalse(answer);
			}
		}
	}

	@Test
	public void test_store_dgk() {
		dgk_pk.writeKey("dgk.pub");
		dgk_sk.writeKey("dgk");
		System.out.println("DGK Write Key");

		DGKPublicKey other_dgk_pub = DGKPublicKey.readKey("dgk.pub");
		System.out.println("DGK Public Read");
		DGKPrivateKey other_dgk_private = DGKPrivateKey.readKey("dgk");
		System.out.println("DGK Public Read");

		assertEquals(dgk_pk, other_dgk_pub);
		assertEquals(dgk_sk, other_dgk_private);
		System.out.println("READ/WRITE TEST ON DGK DONE");
	}

	@Test
	public void test_store_paillier() {
		pk.writeKey("paillier.pub");
		sk.writeKey("paillier");

		PaillierPublicKey other_paillier_pub = PaillierPublicKey.readKey("paillier.pub");
		PaillierPrivateKey other_paillier_private = PaillierPrivateKey.readKey("paillier");

		assertEquals(pk, other_paillier_pub);
		assertEquals(sk, other_paillier_private);
		System.out.println("READ/WRITE TEST ON PAILLIER DONE");
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
