

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import security.DGK.DGKOperations;
import security.DGK.DGKPublicKey;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamal_Ciphertext;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;
import security.socialistmillionaire.alice;


import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

// Client
public class Alice implements Runnable
{
	private static alice Niu = null;
	
	private static PaillierPublicKey pk;
	private static DGKPublicKey pubKey;
	private static ElGamalPublicKey e_pk;
	
	// Get your test data...
	private static BigInteger [] low = generate_low();
	private static BigInteger [] mid = generate_mid();
	private static BigInteger [] high = generate_high();
	
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
	
	// This would have been in Alice's (Client) Main Function
	public void run() {
		try 
		{
		      	ObjectInputStream fromBob = null;
			ObjectOutputStream toBob = null;

			// Wait then connect!
			System.out.println("Alice sleeps...");
			Thread.sleep(4 * 1000);
			System.out.println("Alice woke up...");
			
			Socket bob_socket = new Socket("127.0.0.1", 9254);
			toBob = new ObjectOutputStream(bob_socket.getOutputStream());
			fromBob = new ObjectInputStream(bob_socket.getInputStream());

			Niu = new alice(bob_socket);
			pk = Niu.getPaillierPublicKey();
			pubKey = Niu.getDGKPublicKey();
			e_pk = Niu.getElGamalPublicKey();
			
			// Read object from Bob
        		Object x = fromBob.readObject();
        		BigInteger firstNumberEncrypted = (BigInteger) x;

			// Test K-min
			k_min();
			
			// Test Protocol 1 - 4 Functionality
			alice_demo();
			alice_demo_ElGamal();
		}
		catch (ClassNotFoundException | IOException e) 
		{
			e.printStackTrace();
		} 
		catch (HomomorphicException e) 
		{
			e.printStackTrace();
		}
		catch (InterruptedException e)
		{
			e.printStackTrace();
		}
	}
	
	public static void k_min() 
			throws ClassNotFoundException, IOException, HomomorphicException
	{
		List<ElGamal_Ciphertext> t = new ArrayList<ElGamal_Ciphertext>();
		BigInteger [] toSort = new BigInteger[low.length];
		
		// Test Paillier Sorting
		Niu.setDGKMode(false);
		for(int i = 0; i < low.length;i++)
		{
			toSort[i] = NTL.generateXBitRandom(9);
			toSort[i] = PaillierCipher.encrypt(toSort[i], pk);
		}
		Niu.getKMin(toSort, 3);
		
		// Test DGK Sorting	
		Niu.setDGKMode(true);
		for(int i = 0; i < low.length;i++)
		{
			toSort[i] = NTL.generateXBitRandom(9);
			toSort[i] = DGKOperations.encrypt(toSort[i], pubKey);
		}
		Niu.getKMin(toSort, 3);
		
		// Test ElGamal Sorting
		for(int i = 0; i < low.length;i++)
		{
			toSort[i] = NTL.generateXBitRandom(9);
			t.add(ElGamalCipher.encrypt(toSort[i], e_pk));
		}
		if(e_pk.ADDITIVE)
		{
			Niu.getKMin_ElGamal(t, 3);
		}
	}

	public static void alice_demo() throws ClassNotFoundException, IOException, HomomorphicException
	{	
		// Check the multiplication, DGK
		Niu.setDGKMode(true);
		System.out.println("Testing Multiplication with DGK");
		Niu.multiplication(DGKOperations.encrypt(new BigInteger("1000"), pubKey), 
				DGKOperations.encrypt(new BigInteger("2"), pubKey));
		Niu.multiplication(DGKOperations.encrypt(new BigInteger("1000"), pubKey), 
				DGKOperations.encrypt(new BigInteger("3"), pubKey));
		Niu.multiplication(DGKOperations.encrypt(new BigInteger("1000"), pubKey), 
				DGKOperations.encrypt(new BigInteger("5"), pubKey));
		
		// Check the multiplication, Paillier
		Niu.setDGKMode(false);
		System.out.println("Testing Multiplication with Paillier");
		Niu.multiplication(PaillierCipher.encrypt(new BigInteger("1000"), pk), 
				PaillierCipher.encrypt(new BigInteger("2"), pk));
		Niu.multiplication(PaillierCipher.encrypt(new BigInteger("1000"), pk), 
				PaillierCipher.encrypt(new BigInteger("3"), pk));
		Niu.multiplication(PaillierCipher.encrypt(new BigInteger("1000"), pk), 
				PaillierCipher.encrypt(new BigInteger("50"), pk));

		// Test Protocol 3, mode doesn't matter as DGK is always used!
		System.out.println("Protocol 3 Tests...");
		for(BigInteger l: low)
		{
			System.out.println(Niu.Protocol3(l));
		}
		for(BigInteger l: mid)
		{
			System.out.println(Niu.Protocol3(l));
		}
		for(BigInteger l: high)
		{
			System.out.println(!Niu.Protocol3(l));
		}
		for(BigInteger l: high)
		{
			System.out.println(!Niu.Protocol3(l));
		}
		for(BigInteger l: mid)
		{
			System.out.println(!Niu.Protocol3(l));
		}
		
		// Test Protocol 1
		for(BigInteger l: low)
		{
			System.out.println(Niu.Protocol1(l));
		}
		for(BigInteger l: mid)
		{
			System.out.println(Niu.Protocol1(l));
		}
		for(BigInteger l: high)
		{
			System.out.println(!Niu.Protocol1(l));
		}
		
		// Test Modified Protocol 3, mode doesn't matter as DGK is always used!
		System.out.println("Modified Protocol 3 Tests...");
		for(BigInteger l: low)
		{
			System.out.println(Niu.Modified_Protocol3(l));
		}
		for(BigInteger l: mid)
		{
			System.out.println(Niu.Modified_Protocol3(l));
		}
		for(BigInteger l: high)
		{
			System.out.println(!Niu.Modified_Protocol3(l));
		}
		
		// Test Protocol 2 (Builds on Protocol 3). REMEMEBER [X >= Y]
		// Paillier
		System.out.println("Protocol 2 Tests...Paillier");
		Niu.setDGKMode(false);
		for (int i = 0; i < low.length;i++)
		{
			System.out.println(!Niu.Protocol2(PaillierCipher.encrypt(low[i], pk), 
					PaillierCipher.encrypt(mid[i], pk)));
			System.out.println(Niu.Protocol2(PaillierCipher.encrypt(mid[i], pk), 
					PaillierCipher.encrypt(mid[i], pk)));
			System.out.println(Niu.Protocol2(PaillierCipher.encrypt(high[i], pk), 
					PaillierCipher.encrypt(mid[i], pk)));
		}
		
		// DGK
		System.out.println("Protocol 2 Tests...DGK...SKIPPED!");
		
		// Paillier, Protocol 4 returns (X >= Y)
		System.out.println("Protocol 4 Tests...Paillier");
		Niu.setDGKMode(false);
		for (int i = 0; i < low.length;i++)
		{
			System.out.println(!Niu.Protocol4(PaillierCipher.encrypt(low[i], pk), 
					PaillierCipher.encrypt(mid[i], pk)));
			System.out.println(Niu.Protocol4(PaillierCipher.encrypt(mid[i], pk), 
					PaillierCipher.encrypt(mid[i], pk)));
			System.out.println(Niu.Protocol4(PaillierCipher.encrypt(high[i], pk), 
					PaillierCipher.encrypt(mid[i], pk)));
		}
		
		// DGK, Protocol 4 returns (X > Y)
		Niu.setDGKMode(true);
		System.out.println("Protocol 4 Tests...DGK");
		for (int i = 0; i < low.length;i++)
		{
			System.out.println(!Niu.Protocol4(DGKOperations.encrypt(low[i], pubKey), 
					DGKOperations.encrypt(mid[i], pubKey)));
			System.out.println(!Niu.Protocol4(DGKOperations.encrypt(mid[i], pubKey), 
					DGKOperations.encrypt(mid[i], pubKey)));
			System.out.println(Niu.Protocol4(DGKOperations.encrypt(high[i], pubKey), 
					DGKOperations.encrypt(mid[i], pubKey)));
		}
		
		// Division Test, Paillier
		// REMEMBER THE OUTPUT IS THE ENCRYPTED ANSWER, ONLY BOB CAN VERIFY THE ANSWER
		Niu.setDGKMode(false);
		System.out.println("Division Tests...Paillier");
		BigInteger D = PaillierCipher.encrypt(160, pk);
		BigInteger d = DGKOperations.encrypt(160, pubKey);
		
		Niu.division(D, 2);//160/2 = 50
		Niu.division(D, 3);//160/3 = 33
		Niu.division(D, 4);//160/4 = 25
		Niu.division(D, 5);//160/5 = 20
		Niu.division(D, 25);//160/25 = 4

		Niu.setDGKMode(true);
		System.out.println("Division Tests...DGK");
		Niu.division(d, 2);//160/2 = 50
		Niu.division(d, 3);//160/3 = 33
		Niu.division(d, 4);//160/4 = 25
		Niu.division(d, 5);//160/5 = 20
		Niu.division(d, 25);//160/25 = 4
	}
	
	public static void alice_demo_ElGamal() throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException
	{
		if(!e_pk.ADDITIVE)
		{
			System.out.println("ElGamal Secure Addition/Subtraction");
			// Addition
			Niu.addition(ElGamalCipher.encrypt(new BigInteger("100"), e_pk), ElGamalCipher.encrypt(new BigInteger("160"), e_pk));
			Niu.addition(ElGamalCipher.encrypt(new BigInteger("400"), e_pk), ElGamalCipher.encrypt(new BigInteger("400"), e_pk));
			Niu.addition(ElGamalCipher.encrypt(new BigInteger("1000"), e_pk), ElGamalCipher.encrypt(new BigInteger("1600"), e_pk));
			// Subtract
			Niu.addition(ElGamalCipher.encrypt(new BigInteger("100"), e_pk), ElGamalCipher.encrypt(new BigInteger("160"), e_pk));
			Niu.addition(ElGamalCipher.encrypt(new BigInteger("400"), e_pk), ElGamalCipher.encrypt(new BigInteger("160"), e_pk));
			Niu.addition(ElGamalCipher.encrypt(new BigInteger("1000"), e_pk), ElGamalCipher.encrypt(new BigInteger("160"), e_pk));
			return;
		}
		System.out.println("Multiplication Tests...ElGamal");
		// Check the multiplication, ElGamal
		Niu.multiplication(ElGamalCipher.encrypt(new BigInteger("100"), e_pk), 
				ElGamalCipher.encrypt(new BigInteger("2"), e_pk));
		Niu.multiplication(ElGamalCipher.encrypt(new BigInteger("1000"), e_pk), 
				ElGamalCipher.encrypt(new BigInteger("3"), e_pk));
		Niu.multiplication(ElGamalCipher.encrypt(new BigInteger("1000"), e_pk), 
				ElGamalCipher.encrypt(new BigInteger("50"), e_pk));
		
		System.out.println("Division Tests...ElGamal");
		Niu.division(ElGamalCipher.encrypt(160, e_pk), 2);//160/2 = 50
		Niu.division(ElGamalCipher.encrypt(160, e_pk), 3);//160/3 = 33
		Niu.division(ElGamalCipher.encrypt(160, e_pk), 4);//160/4 = 25
		Niu.division(ElGamalCipher.encrypt(160, e_pk), 5);//160/5 = 20
		Niu.division(ElGamalCipher.encrypt(160, e_pk), 25);//160/25 = 4
		
		// ElGamal
		System.out.println("Protocol 4 Tests...ElGamal");
		for (int i = 0; i < low.length;i++)
		{
			System.out.println(!Niu.Protocol4(ElGamalCipher.encrypt(low[i], e_pk), 
					ElGamalCipher.encrypt(mid[i], e_pk)));
			System.out.println(Niu.Protocol4(ElGamalCipher.encrypt(mid[i], e_pk), 
					ElGamalCipher.encrypt(mid[i], e_pk)));
			System.out.println(Niu.Protocol4(ElGamalCipher.encrypt(high[i], e_pk), 
					ElGamalCipher.encrypt(mid[i], e_pk)));
		}
	}
}
