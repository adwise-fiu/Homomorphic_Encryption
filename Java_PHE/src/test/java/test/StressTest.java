package test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.List;

import security.DGK.DGKOperations;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.DGK.DGKSignature;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamalSignature;
import security.elgamal.ElGamal_Ciphertext;
import security.gm.GMCipher;
import security.gm.GMPrivateKey;
import security.gm.GMPublicKey;
import security.misc.CipherConstants;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;
import security.paillier.PaillierSignature;
import security.socialistmillionaire.alice;
import security.socialistmillionaire.bob;

public class StressTest 
{
	private static final int TEST = 100;
	private static final int SIZE = 100000; // Stress-Test
	private static final int KEY_SIZE = 1024;
	private static final int BILLION = BigInteger.TEN.pow(9).intValue();
	
	// ------------------Stress Test Protocols alice------------------------------------------------
	public static void alice_Paillier(alice Niu) 
			throws ClassNotFoundException, IOException, HomomorphicException
	{
		System.out.println("Start Paillier Test");
		Niu.setDGKMode(false);
		long start;
		BigInteger x = NTL.generateXBitRandom(15);
		BigInteger y = NTL.generateXBitRandom(15);
		BigInteger a = NTL.generateXBitRandom(15);
		System.out.println("x: " + x);
		System.out.println("y: " + y);
		System.out.println("a: " + a);
		System.out.println("N: " + Niu.getPaillierPublicKey().getN());
		x = PaillierCipher.encrypt(x, Niu.getPaillierPublicKey());
		y = PaillierCipher.encrypt(y, Niu.getPaillierPublicKey());
		
		// MULTIPLICATION
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.multiplication(x, y);
		}
		System.out.println("Multiplication, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// DIVISION
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.division(x, 1600);
		}
		System.out.println("Division, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// PROTOCOL 1
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Protocol1(a);
		}
		System.out.println("Protocol 1, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// PROTOCOL 2
		if(!Niu.isDGK())
		{
			start = System.nanoTime();
			for(int i = 0; i < TEST; i++)
			{
				Niu.Protocol2(x, y);
			}
			System.out.println("Protocol 2, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");	
		}
		
		// PROTOCOL 3
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Protocol3(a);
		}
		System.out.println("Protocol 3, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// Modified Protocol 3
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Modified_Protocol3(a);
		}
		System.out.println("Modified Protocol 3, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// PROTOCOL 4
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Protocol4(x, y);
		}
		System.out.println("Protocol 4, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
	}
	
	public static void alice_DGK(alice Niu)
			throws ClassNotFoundException, IOException, HomomorphicException
	{
		System.out.println("Start DGK Test");
		long start;
		Niu.setDGKMode(true);
		BigInteger x = NTL.generateXBitRandom(15);
		BigInteger y = NTL.generateXBitRandom(15);
		BigInteger a = NTL.generateXBitRandom(15);
		System.out.println("x: " + x);
		System.out.println("y: " + y);
		System.out.println("a: " + a);
		System.out.println("u: " + Niu.getDGKPublicKey().getU());
		x = DGKOperations.encrypt(x, Niu.getDGKPublicKey());
		y = DGKOperations.encrypt(y, Niu.getDGKPublicKey());
		
		// MULTIPLICATION
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.multiplication(x, y);
		}
		System.out.println("Multiplication, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// DIVISION
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.division(x, 1600);
		}
		System.out.println("Division, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// PROTOCOL 1
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Protocol1(a);
		}
		System.out.println("Protocol 1, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// PROTOCOL 2
		if(!Niu.isDGK())
		{
			start = System.nanoTime();
			for(int i = 0; i < TEST; i++)
			{
				Niu.Protocol2(x, y);
			}
			System.out.println("Protocol 2, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		}
		else
		{
			System.out.println("Protocol 2, does not work for comparing two DGK encrypted values!");
		}
		
		// PROTOCOL 3
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Protocol3(a);
		}
		System.out.println("Protocol 3, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Modified_Protocol3(a);
		}
		System.out.println("Modified Protocol 3, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// PROTOCOL 4
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Protocol4(x, y);
		}
		System.out.println("Protocol 4, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
	}
	
	public static void alice_ElGamal(alice Niu) 
			throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException
	{
		System.out.println("Start ElGamal Test");
		long start;
		BigInteger _x = NTL.generateXBitRandom(15);
		BigInteger _y = NTL.generateXBitRandom(15);
		BigInteger a = NTL.generateXBitRandom(15);
		System.out.println("x : " + _x);
		System.out.println("y : " + _y);
		System.out.println("a : " + a);
		System.out.println("u : " + CipherConstants.FIELD_SIZE);
		ElGamal_Ciphertext x = ElGamalCipher.encrypt(_x, Niu.getElGamalPublicKey());
		ElGamal_Ciphertext y = ElGamalCipher.encrypt(_y, Niu.getElGamalPublicKey());
		
		if(!Niu.getElGamalPublicKey().ADDITIVE)
		{
			start = System.nanoTime();
			for(int i = 0; i < TEST; i++)
			{
				Niu.addition(x, y);
			}
			System.out.println("Addition, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
			return;
		}
		// MULTIPLICATION
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.multiplication(x, y);
		}
		System.out.println("Multiplication, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");

		// DIVISION
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.division(x, 100);
		}
		System.out.println("Division, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// PROTOCOL 1
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Protocol1(a);
		}
		System.out.println("Protocol 1, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// PROTOCOL 2
		System.out.println("Protocol 2, doesn't work for comparing two ElGamal encrypted values!");
		
		// PROTOCOL 3
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Protocol3(a);
		}
		System.out.println("Protocol 3, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// PROTOCOL 3
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Modified_Protocol3(a);
		}
		System.out.println("Modified Protocol 3, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
		
		// PROTOCOL 4
		start = System.nanoTime();
		for(int i = 0; i < TEST; i++)
		{
			Niu.Protocol4(x, y);
		}
		System.out.println("Protocol 4, Time to complete " + TEST + " tests: " + (System.nanoTime() - start)/BILLION + " seconds");
	}

	// ------------------Stress Test Protocols bob----------------------------------------------

	public static void bob(bob andrew) 
			throws ClassNotFoundException, IOException, HomomorphicException
	{
		BigInteger b = NTL.generateXBitRandom(15);
		System.out.println("b: " + b);
		// Test Code
		for(int i = 0; i < TEST; i++)
		{
			andrew.multiplication();
		}
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.division(100);
		}
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.Protocol1(b);
		}
		
		if(!andrew.isDGK())
		{
			for(int i = 0; i < TEST; i++)
			{
				andrew.Protocol2();
			}
		}
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.Protocol3(b);
		}
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.Modified_Protocol3(b);
		}
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.Protocol4();	
		}
	}
	
	public static void bob_ElGamal(bob andrew) 
			throws ClassNotFoundException, IOException
	{
		
		BigInteger b = NTL.generateXBitRandom(15);
		System.out.println("b: " + b);
		
		if(!andrew.getElGamalPublicKey().ADDITIVE)
		{
			for(int i = 0; i < TEST; i++)
			{
				andrew.addition(true);
			}
			return;
		}
		
		// Test Code
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.ElGamal_multiplication();
		}
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.ElGamal_division(10);
		}
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.Protocol1(b);
		}
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.Protocol3(b);
		}
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.Modified_Protocol3(b);
		}
		
		for(int i = 0; i < TEST; i++)
		{
			andrew.ElGamal_Protocol4();	
		}
	}
	
	//-------------------Stress Test Crypto Methods-------------------------------------------
	
	public static void Paillier_Test(PaillierPublicKey pk, PaillierPrivateKey sk) throws InvalidKeyException, SignatureException, HomomorphicException
	{
		System.out.println("-----------PAILLIER TEST x" + SIZE + "--------------KEY: " + KEY_SIZE + "-----------");
		long start = 0;
		
		PaillierSignature sig = new PaillierSignature();
		sig.initSign(sk);
		sig.update(new BigInteger("42").toByteArray());
		byte [] cert = sig.sign();
		
		start = System.nanoTime();
		for(int i = 0; i < SIZE;i++)
		{
			sig.initVerify(pk);
			sig.update(BigInteger.valueOf(i).toByteArray());
			if(sig.verify(cert))
			{
				System.out.println("PAILLIER VALID AT: " + i);
			}
		}
		System.out.println("Time to complete signature: " + ((System.nanoTime() - start)/BILLION) + " seconds");
		
		BigInteger base = PaillierCipher.encrypt(NTL.generateXBitRandom(15), pk);
		BigInteger t = NTL.generateXBitRandom(15);
		
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			PaillierCipher.encrypt(t, pk);
		}
		System.out.println("Time to complete encryption: " + ((System.nanoTime() - start)/BILLION) + " seconds");
		
		t = PaillierCipher.encrypt(NTL.generateXBitRandom(15), pk);
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			PaillierCipher.decrypt(t, sk);	
		}
		System.out.println("Time to complete decryption: " + ((System.nanoTime() - start)/BILLION) + " seconds");
		
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			PaillierCipher.add(base, t, pk);
		}
		System.out.println("Time to complete addition: " + ((System.nanoTime() - start)/BILLION) + " seconds");

		t = NTL.generateXBitRandom(15);
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			PaillierCipher.multiply(base, t, pk);
		}
		System.out.println("Time to complete multiplication: " + ((System.nanoTime() - start)/BILLION) + " seconds");
	
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			PaillierCipher.add_plaintext(base, t, pk);
		}
		System.out.println("Time to complete addition (plaintext): " + ((System.nanoTime() - start)/BILLION) + " seconds");
	}
	
	
	public static void DGK_Test(DGKPublicKey pubKey, DGKPrivateKey privKey) throws InvalidKeyException, SignatureException, HomomorphicException
	{
		System.out.println("-----------DGK TEST x" + SIZE + "--------------KEY: " + KEY_SIZE + "-----------");
		BigInteger base = DGKOperations.encrypt(NTL.generateXBitRandom(15), pubKey);
		BigInteger t = NTL.generateXBitRandom(15);
		long start = 0;
		
		DGKSignature sig = new DGKSignature();
		sig.initSign(privKey);
		sig.update(new BigInteger("42").toByteArray());
		byte [] cert = sig.sign();

		start = System.nanoTime();
		for(int i = 0; i < SIZE;i++)
		{
			sig.initVerify(pubKey);
			sig.update(BigInteger.valueOf(i).toByteArray());
			if(sig.verify(cert))
			{
				System.out.println("DGK VALID AT: " + i);
			}
		}
		System.out.println("Time to complete signature: " + ((System.nanoTime() - start)/BILLION) + " seconds");
			
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			DGKOperations.encrypt(t, pubKey);
		}
		System.out.println("Time to complete encryption: " + ((System.nanoTime() - start)/BILLION) + " seconds");
	
		t = DGKOperations.encrypt(t, pubKey);
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			DGKOperations.decrypt(t, privKey);
		}
		System.out.println("Time to complete decryption: " + ((System.nanoTime() - start)/BILLION) + " seconds");
		
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			DGKOperations.add(base, t, pubKey);
		}
		System.out.println("Time to complete addition: " + ((System.nanoTime() - start)/BILLION) + " seconds");
	
		long exp =  NTL.generateXBitRandom(15).longValue();
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			DGKOperations.multiply(base, exp, pubKey);
		}
		System.out.println("Time to complete multiplication: " + ((System.nanoTime() - start)/BILLION) + " seconds");

		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			DGKOperations.add_plaintext(base, exp, pubKey);
		}
		System.out.println("Time to complete addition (plaintext): " + ((System.nanoTime() - start)/BILLION) + " seconds");
	}
	
	
	public static void ElGamal_Test(ElGamalPublicKey e_pk, ElGamalPrivateKey e_sk) throws SignatureException, InvalidKeyException
	{
		System.out.println("-----------EL-GAMAL TEST x" + SIZE + "--------------KEY: " + KEY_SIZE + "-----------");

		ElGamal_Ciphertext base = ElGamalCipher.encrypt(NTL.generateXBitRandom(15), e_pk);
		BigInteger t = NTL.generateXBitRandom(15);
		ElGamal_Ciphertext temp = ElGamalCipher.encrypt(t, e_pk);
		
		long start = 0;
		
		ElGamalSignature sig = new ElGamalSignature();
		sig.initSign(e_sk);
		sig.update(new BigInteger("42").toByteArray());
		byte [] cert = sig.sign();

		start = System.nanoTime();
		for(int i = 0; i < SIZE;i++)
		{
			sig.initVerify(e_pk);
			sig.update(BigInteger.valueOf(i).toByteArray());
			if(sig.verify(cert))
			{
				System.out.println("ElGamal VALID AT: " + i);
			}
		}
		System.out.println("Time to complete signature: " + ((System.nanoTime() - start)/BILLION) + " seconds");
		
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{	
			ElGamalCipher.encrypt(t, e_pk);
		}
		System.out.println("Time to complete encryption: " + ((System.nanoTime() - start)/BILLION) + " seconds");
		
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			ElGamalCipher.decrypt(temp, e_sk);
		}
		System.out.println("Time to complete decryption: " + ((System.nanoTime() - start)/BILLION) + " seconds");
		
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			ElGamalCipher.add(temp, base, e_pk);
		}
		System.out.println("Time to complete addition: " + ((System.nanoTime() - start)/BILLION) + " seconds");
		
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			temp = ElGamalCipher.multiply_scalar(temp, t, e_pk);
		}
		System.out.println("Time to complete multiplication: " + ((System.nanoTime() - start)/BILLION) + " seconds");
	}
	
	
	public static void GM_Test(GMPublicKey gm_pk, GMPrivateKey gm_sk) throws HomomorphicException
	{
		System.out.println("-----------GM TEST x" + SIZE + "-----------------KEY: " + KEY_SIZE + "-----------");
		BigInteger t = NTL.generateXBitRandom(15);
		List<BigInteger> enc_t = GMCipher.encrypt(t, gm_pk);
		List<BigInteger> enc_z = GMCipher.encrypt(t, gm_pk);
		long start = 0;
		
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			GMCipher.encrypt(t, gm_pk);
		}
		System.out.println("Time to complete encryption: " + ((System.nanoTime() - start)/BILLION) + " seconds");

		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			GMCipher.decrypt(enc_t, gm_sk);
		}
		System.out.println("Time to complete decryption: " + ((System.nanoTime() - start)/BILLION) + " seconds");
		
		start = System.nanoTime();
		for(int i = 0; i < SIZE; i++)
		{
			GMCipher.xor(enc_t, enc_z, gm_pk);
		}
		System.out.println("Time to complete xor: " + ((System.nanoTime() - start)/BILLION) + " seconds");
	}

	// ------------------------------------ Generate numbers for Protocol 1-4 testing---------------------------
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
}
