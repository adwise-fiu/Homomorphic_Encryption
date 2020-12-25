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

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.List;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class BasicTesting 
{	
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
	public void basic_gm() throws HomomorphicException 
	{
		// Build Paillier Keys
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
}
