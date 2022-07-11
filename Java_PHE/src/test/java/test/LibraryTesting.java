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
import security.DGK.DGKOperations;
import security.DGK.DGKKeyPairGenerator;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.DGK.DGKSignature;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalKeyPairGenerator;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamalSignature;
import security.elgamal.ElGamal_Ciphertext;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class LibraryTesting 
{	
	private static int KEY_SIZE = 1024;
	
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
	
	@BeforeClass
	public static void generate_keys() throws HomomorphicException {
		// Build DGK Keys
		DGKKeyPairGenerator p = new DGKKeyPairGenerator();
		p.initialize(KEY_SIZE, null);
		p.setL(20);
		dgk = p.generateKeyPair();
		
		dgk_pk = (DGKPublicKey) dgk.getPublic();
		dgk_sk = (DGKPrivateKey) dgk.getPrivate();
		
		// Build Paillier Keys
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		p.initialize(KEY_SIZE, null);
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
		BigInteger a = PaillierCipher.encrypt(BigInteger.TEN, pk);
		a = PaillierCipher.decrypt(a, sk);
		assertEquals(BigInteger.TEN, a);
		
		// Test Addition
		a = PaillierCipher.encrypt(a, pk);
		a = PaillierCipher.add(a, a, pk);//20
		assertEquals(new BigInteger("20"), PaillierCipher.decrypt(a, sk));
		
		// Test Subtraction
		a = PaillierCipher.subtract(a, PaillierCipher.encrypt(BigInteger.TEN, pk), pk);// 20 - 10
		assertEquals(BigInteger.TEN, PaillierCipher.decrypt(a, sk));
		
		// Test Multiplication
		a = PaillierCipher.multiply(a, BigInteger.TEN, pk); // 10 * 10
		assertEquals(new BigInteger("100"), PaillierCipher.decrypt(a, sk));
		
		// Test Division
		a = PaillierCipher.divide(a, new BigInteger("2"), pk); // 100/2 
		assertEquals(new BigInteger("50"), PaillierCipher.decrypt(a, sk));
	}
	
	// NOTE: THIS IS THE MULTIPLICATIVE VERSION
	@Test
	public void basic_ElGamal_multiply() throws HomomorphicException {
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
	public void basic_ElGamal_add() throws HomomorphicException {
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
	public void signature_test() throws HomomorphicException, InvalidKeyException, SignatureException {
		byte [] signed_answer = null;
		
		// Paillier Signature
		PaillierSignature paillier = new PaillierSignature();
		paillier.initSign(sk);
		paillier.update(new BigInteger("42").toByteArray());
		signed_answer = paillier.sign();
		
		// Test signatures
		paillier.initVerify(pk);
		for (int i = 0; i < 1000; i++) {
			paillier.update(BigInteger.valueOf(i).toByteArray());
			boolean answer = paillier.verify(signed_answer);
			if (i == 42) {
				//assertEquals(answer, true);
			}
			else {
				assertEquals(answer, false);
			}
		}
		
		// ElGamal Signature
		ElGamalSignature elgamal_sign = new ElGamalSignature();
		elgamal_sign.initSign(el_sk);
		elgamal_sign.update(new BigInteger("42").toByteArray());
		signed_answer = elgamal_sign.sign();
		
		// Test signatures
		elgamal_sign.initVerify(el_pk);
		for (int i = 0; i < 1000; i++)
		{
			elgamal_sign.update(BigInteger.valueOf(i).toByteArray());
			if (i == 42) {
				assertEquals(elgamal_sign.verify(signed_answer), true);
			}
			else {
				assertEquals(elgamal_sign.verify(signed_answer), false);
			}
		}
		
		// NOTE: DGK SIGNATURE IS NOT PEER REVIEWED!!!!!!!
		DGKSignature dgk_sign = new DGKSignature();
		dgk_sign.initSign(dgk_sk);
		dgk_sign.update(new BigInteger("42").toByteArray());
		signed_answer = dgk_sign.sign();
		
		// Test signatures
		dgk_sign.initVerify(dgk_pk);
		for (int i = 0; i < 1000; i++) {
			dgk_sign.update(BigInteger.valueOf(i).toByteArray());
			if (i == 42) {
				assertEquals(dgk_sign.verify(signed_answer), true);
			}
			else {
				assertEquals(dgk_sign.verify(signed_answer), false);
			}
		}
	}
	
	@Test
	public void basic_gm() throws HomomorphicException 
	{
		// Build GoldWasser-Micali Keys
		GMKeyPairGenerator p = new GMKeyPairGenerator();
		p.initialize(1024, null);
		KeyPair pe = p.generateKeyPair();
		
		GMPublicKey pk = (GMPublicKey) pe.getPublic();
		GMPrivateKey sk = (GMPrivateKey) pe.getPrivate();
		
		// Test D(E(X)) = X
		List<BigInteger> a = GMCipher.encrypt(BigInteger.TEN, pk);
		assertEquals(BigInteger.TEN, GMCipher.decrypt(a, sk));
		
		// Test XOR
		BigInteger [] c = GMCipher.xor(a, a, pk);
		assertEquals(BigInteger.ZERO, GMCipher.decrypt(c, sk));
	}
	
	@Test
	public void integration_test()
	{
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
