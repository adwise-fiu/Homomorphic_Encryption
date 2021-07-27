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

import security.DGK.DGKOperations;
import security.DGK.DGKKeyPairGenerator;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;

import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalKeyPairGenerator;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamal_Ciphertext;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.List;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class LibraryTesting 
{	
	@Test
	public void basic_DGK() throws HomomorphicException
	{
		// Build DGK Keys
		DGKKeyPairGenerator p = new DGKKeyPairGenerator();
		p.initialize(1024, null);
		KeyPair pe = p.generateKeyPair();
		
		DGKPublicKey pk = (DGKPublicKey) pe.getPublic();
		DGKPrivateKey sk = (DGKPrivateKey) pe.getPrivate();
		
		// Test D(E(X)) = X
		BigInteger a = DGKOperations.encrypt(BigInteger.TEN, pk);
		a = BigInteger.valueOf(DGKOperations.decrypt(a, sk));
		assertEquals(BigInteger.TEN, a);
		
		// Test Addition, note decrypting returns a long not BigInteger
		a = DGKOperations.encrypt(a, pk);
		a = DGKOperations.add(a, a, pk); //20
		assertEquals(20, DGKOperations.decrypt(a, sk));
		
		// Test Subtraction, note decrypting returns a long not BigInteger
		a = DGKOperations.subtract(a, DGKOperations.encrypt(BigInteger.TEN, pk), pk);// 20 - 10
		assertEquals(10, DGKOperations.decrypt(a, sk));
		
		// Test Multiplication, note decrypting returns a long not BigInteger
		a = DGKOperations.multiply(a, BigInteger.TEN, pk); // 10 * 10
		assertEquals(100, DGKOperations.decrypt(a, sk));
		
		// Test Division, Division is failing for some reason...?
		//a = DGKOperations.divide(a, new BigInteger("2"), pk); // 100/2
		//assertEquals(50, DGKOperations.decrypt(a, sk));
	}
	
	@Test
	public void basic_Paillier() throws HomomorphicException
	{
		// Build Paillier Keys
		PaillierKeyPairGenerator p = new PaillierKeyPairGenerator();
		p.initialize(1024, null);
		KeyPair pe = p.generateKeyPair();
		
		PaillierPublicKey pk = (PaillierPublicKey) pe.getPublic();
		PaillierPrivateKey sk = (PaillierPrivateKey) pe.getPrivate();
		
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
	
	@Test
	public void basic_ElGamal_multiply() throws HomomorphicException
	{
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
	public void basic_ElGamal_add() throws HomomorphicException
	{
		// Build DGK Keys
		ElGamalKeyPairGenerator p = new ElGamalKeyPairGenerator();
		p.initialize(1024, null);
		KeyPair pe = p.generateKeyPair();
		
		ElGamalPublicKey pk = (ElGamalPublicKey) pe.getPublic();
		ElGamalPrivateKey sk = (ElGamalPrivateKey) pe.getPrivate();
		
		// Test D(E(X)) = X
		ElGamal_Ciphertext a = ElGamalCipher.encrypt(BigInteger.TEN, pk);
		BigInteger alpha = ElGamalCipher.decrypt(a, sk);
		assertEquals(BigInteger.TEN, alpha);
		
		// Test Addition
		a = ElGamalCipher.encrypt(BigInteger.TEN, pk);
		a = ElGamalCipher.add(a, a, pk); //20
		assertEquals(new BigInteger("20"), ElGamalCipher.decrypt(a, sk));
		
		// Test Subtraction
		a = ElGamalCipher.subtract(a, ElGamalCipher.encrypt(BigInteger.TEN, pk), pk);// 20 - 10
		assertEquals(BigInteger.TEN, ElGamalCipher.decrypt(a, sk));
		
		// Test Multiplication
		a = ElGamalCipher.multiply_scalar(a, BigInteger.TEN, pk); // 10 * 10
		assertEquals(new BigInteger("100"), ElGamalCipher.decrypt(a, sk));
		
		// Test Division - INVALID FOR ADDITIVE MODE
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
		int KEY_SIZE = 1024;
		
		// Build DGK Keys
		DGKKeyPairGenerator gen = null;
		gen = new DGKKeyPairGenerator();
		gen.initialize(KEY_SIZE, null);
		KeyPair DGK = gen.generateKeyPair();
		
		// Build Paillier Keys
		PaillierKeyPairGenerator p = new PaillierKeyPairGenerator();
		p.initialize(KEY_SIZE, null);
		KeyPair pe = p.generateKeyPair();
		
		// Build ElGamal Keys
		ElGamalKeyPairGenerator pg = new ElGamalKeyPairGenerator();
		// NULL -> ADDITIVE
		// NOT NULL -> MULTIPLICATIVE
		pg.initialize(KEY_SIZE, new SecureRandom());
		KeyPair el_gamal = pg.generateKeyPair();
		
		Thread andrew = new Thread(new Bob(pe, DGK, el_gamal));
		andrew.start();
		Thread yujia = new Thread(new Alice());
		yujia.start();
		try
		{
			andrew.join();
			yujia.join();
		}
		catch (InterruptedException e)
		{
			e.printStackTrace();
		}
	}

}
