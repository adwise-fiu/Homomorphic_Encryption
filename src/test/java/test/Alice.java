package test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import security.dgk.DGKOperations;
import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamal_Ciphertext;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;
import security.socialistmillionaire.alice;

// Client
public class Alice implements Runnable
{
	private static alice Niu = null;
	
	private static PaillierPublicKey pk;
	private static DGKPublicKey pubKey;
	private static ElGamalPublicKey e_pk;
	
	private static PaillierPrivateKey sk;
	private static DGKPrivateKey privKey;
	private static ElGamalPrivateKey e_sk;
	
	// Get your test data...
	private static final BigInteger [] low = StressTest.generate_low();
	private static final BigInteger [] mid = StressTest.generate_mid();
	private static final BigInteger [] high = StressTest.generate_high();
	
	// This would have been in Alice's (Client) Main Function
	public void run() {
		try 
		{
			// Wait then connect!
			System.out.println("Alice sleeps...");
			Thread.sleep(2 * 1000);
			System.out.println("Alice woke up...");
			Niu = new alice(new Socket("127.0.0.1", 9254));
			Niu.receivePublicKeys();
			pk = Niu.getPaillierPublicKey();
			pubKey = Niu.getDGKPublicKey();
			e_pk = Niu.getElGamalPublicKey();
			
			// Get Private Keys from Bob
			// This is only for verifying tests...
			sk = (PaillierPrivateKey) Niu.readObject();
			privKey = (DGKPrivateKey) Niu.readObject();
			e_sk = (ElGamalPrivateKey) Niu.readObject();
			
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

	public static void alice_demo() throws ClassNotFoundException, IOException, HomomorphicException {
		boolean result;
		System.out.println("Please note all printed values should return true...");
		BigInteger temp;
		long temp_value;
		
		// Check the multiplication, DGK
		Niu.setDGKMode(true);
		System.out.println("Testing Multiplication with DGK");
		temp = Niu.multiplication(DGKOperations.encrypt(new BigInteger("1000"), pubKey), 
				DGKOperations.encrypt(new BigInteger("2"), pubKey));
		temp_value = DGKOperations.decrypt(temp, privKey);
		assert (temp_value == 2000);
		
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
		for(BigInteger l: low) {
			result = Niu.Protocol3(l);
			System.out.println(result);
		}
		for(BigInteger l: mid) {
			result = Niu.Protocol3(l);
			System.out.println(result);
		}
		for(BigInteger l: high) {
			result = Niu.Protocol3(l);
			System.out.println(!result);
		}
		for(BigInteger l: high) {
			result = Niu.Protocol3(l);
			System.out.println(!result);
		}
		for(BigInteger l: mid) {
			result = Niu.Protocol3(l);
			System.out.println(!result);
		}
		
		// Test Protocol 1
		for(BigInteger l: low) {
			System.out.println(Niu.Protocol1(l));
		}
		for(BigInteger l: mid) {
			System.out.println(Niu.Protocol1(l));
		}
		for(BigInteger l: high) {
			System.out.println(!Niu.Protocol1(l));
		}
		
		// Test Modified Protocol 3, mode doesn't matter as DGK is always used!
		// Will be compared against mid
		System.out.println("Modified Protocol 3 Tests...");
		for(BigInteger l: low) {
			result = Niu.Modified_Protocol3(l);
			System.out.println("Modified Protcool 3, X < Y: " + result);
		}
		for(BigInteger l: mid)
		{
			result = Niu.Modified_Protocol3(l);
			System.out.println("Modified Protocol 3, X == Y: " + result);
		}
		for(BigInteger l: high)
		{
			result = Niu.Modified_Protocol3(l);
			System.out.println("Modified Protocol 3, X > Y: " + !result);
		}
		
		// Test Protocol 2 (Builds on Protocol 3). REMEMBER [X >= Y]
		// Paillier
		System.out.println("Protocol 2 Tests...Paillier");
		Niu.setDGKMode(false);
		for (int i = 0; i < low.length;i++) {
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
		for (int i = 0; i < low.length;i++) {
			// X < Y - RETURNS FALSE
			System.out.println(!Niu.Protocol4(PaillierCipher.encrypt(low[i], pk), 
					PaillierCipher.encrypt(mid[i], pk)));
			// X == Y - RETURNS FALSE
			System.out.println(Niu.Protocol4(PaillierCipher.encrypt(mid[i], pk), 
					PaillierCipher.encrypt(mid[i], pk)));
			// X >= Y - RETURNS FALSE
			System.out.println(Niu.Protocol4(PaillierCipher.encrypt(high[i], pk), 
					PaillierCipher.encrypt(mid[i], pk)));
		}
		
		// DGK, Protocol 4 returns (X > Y)
		Niu.setDGKMode(true);
		System.out.println("Protocol 4 Tests...DGK");
		for (int i = 0; i < low.length;i++) {
			// X < Y - RETURNS FALSE
			System.out.println(!Niu.Protocol4(DGKOperations.encrypt(low[i], pubKey), 
					DGKOperations.encrypt(mid[i], pubKey)));
			// X == Y - RETURNS FALSE
			System.out.println(!Niu.Protocol4(DGKOperations.encrypt(mid[i], pubKey), 
					DGKOperations.encrypt(mid[i], pubKey)));
			// X > Y - RETURNS TRUE
			System.out.println(Niu.Protocol4(DGKOperations.encrypt(high[i], pubKey), 
					DGKOperations.encrypt(mid[i], pubKey)));
		}
		// Protocol 4, Spyridion Request
		System.out.println("Spyridion Test Starting...");
		Niu.setDGKMode(true);
		System.out.println(Niu.Protocol4(DGKOperations.encrypt(100, pubKey), 
				DGKOperations.encrypt(98, pubKey)));
		System.out.println(Niu.Protocol4(DGKOperations.encrypt(10, pubKey), 
				DGKOperations.encrypt(8, pubKey)));
		System.out.println("Spyridion Test Ending...");
		
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
