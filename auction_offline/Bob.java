
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;

import security.misc.HomomorphicException;
import security.socialistmillionaire.bob;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;

// Server-side
public class Bob implements Runnable
{
	// Initialize Alice and Bob
	private static ServerSocket bob_socket = null;
	private static Socket bob_client = null;
	private static bob andrew = null;
	
	// Get your test data...
	private static BigInteger [] low = generate_low();
	private static BigInteger [] mid = generate_mid();
	
	private KeyPair p;
	private KeyPair d;
	private KeyPair e;


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
	
	public Bob(KeyPair paillier, KeyPair dgk, KeyPair elgamal)
	{
		this.p = paillier;
		this.d = dgk;
		this.e = elgamal;
	}
	
	// This could would be in Bob's Main Method
	public void run() {
		try
		{
		    	ObjectInputStream fromAlice = null;
			ObjectOutputStream toAlice = null;
			
			PaillierPublicKey pk = (PaillierPublicKey) this.p.getPublic();
			BigInteger encrypted_bob = PaillierCipher.encrypt(new BigInteger("9001"), pk);

			bob_socket = new ServerSocket(9254);
			System.out.println("Bob is ready...");
			bob_client = bob_socket.accept();

			// Create communication to Alice
			toAlice = new ObjectOutputStream(bob_client.getOutputStream());
			fromAlice = new ObjectInputStream(bob_client.getInputStream());
			
			// Set up Alice/Bob connection
			andrew = new bob(bob_client, this.p, this.d, this.e);
			
    			// Send the encrypted number to Alice
    			toAlice.writeObject(encrypted_bob);
    			toAlice.flush();
    			
			// Test K-Min using Protocol 4
			// Line 99 in Alice matches to Line 158-165 in Bob
			andrew.setDGKMode(false);
			andrew.run();// Sort Paillier
			andrew.setDGKMode(true);
			andrew.run();// Sort DGK
			if(andrew.getElGamalPublicKey().ADDITIVE)
			{
				andrew.repeat_ElGamal_Protocol4();
			}

			// Lines 162-163 in Alice matches to Line 167-168 in Bob
			bob_demo();
			bob_demo_ElGamal();
		}
		catch (IOException | ClassNotFoundException x)
		{
			x.printStackTrace();
		}
		catch(IllegalArgumentException o)
		{
			o.printStackTrace();
		} 
		catch (HomomorphicException e) {
			e.printStackTrace();
		}
		finally
		{
			try 
			{
				if(bob_client != null)
				{
					bob_client.close();
				}
				if(bob_socket != null)
				{
					bob_socket.close();
				}
			}
			catch (IOException e) 
			{
				e.printStackTrace();
			}
		}
	}
	
	// ------------------------------------ Basic demo methods-------------------------------------
	public static void bob_demo() throws ClassNotFoundException, IOException, HomomorphicException
	{
		// Test out-source multiplication, DGK
		andrew.setDGKMode(true);
		for(int i = 0; i < 3; i++)
		{
			andrew.multiplication();
		}
		andrew.setDGKMode(false);
		for(int i = 0; i < 3; i++)
		{
			andrew.multiplication();
		}
		System.out.println("Finished Testing Multiplication");
		
		// Test Protocol 3
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Protocol3(mid[i % 16]);
		}
		for(int i = 0; i < 16 * 2; i++)
		{
			andrew.Protocol3(low[i % 16]);
		}
		System.out.println("Finished Testing Protocol 3");

		// Test Protocol 1
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Protocol1(mid[i % 16]);
		}
		System.out.println("Finished Testing Protocol 1");

		// Test Modified Protocol 3
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Modified_Protocol3(mid[i % 16]);
		}
		System.out.println("Finished Testing Modified Protocol 3");
		
		// Test Protocol 2 with Paillier
		andrew.setDGKMode(false);
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Protocol2();
		}
		System.out.println("Finished Testing Protocol 2 w/ Paillier");
		
		// Test Protocol 2 with ElGamal
		System.out.println("Finished Testing Protocol 2 w/ ElGamal");
		
		
		// Test Protocol 4 with Paillier
		andrew.setDGKMode(false);
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Protocol4();
		}
		System.out.println("Finished Testing Protocol 4 w/ Paillier");
			
		// Test Protocol 4 with DGK
		andrew.setDGKMode(true);
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.Protocol4();
		}
				
		System.out.println("Finished Testing Protocol 4 w/ DGK");
		// Division Protocol Test, Paillier
		andrew.setDGKMode(false);
		andrew.division(2);
		andrew.division(3);
		andrew.division(4);
		andrew.division(5);
		andrew.division(25);
		
		// Division Test, DGK
		andrew.setDGKMode(true);
		andrew.division(2);
		andrew.division(3);
		andrew.division(4);
		andrew.division(5);
		andrew.division(25);
	}
	
	//--------------------------Basic demo methods with ElGamal------------------------------------------	
	
	public static void bob_demo_ElGamal() throws ClassNotFoundException, IOException
	{
		if(!andrew.getElGamalPublicKey().ADDITIVE)
		{
			// Addition
			andrew.addition(true);
			andrew.addition(true);
			andrew.addition(true);
			// Subtract
			andrew.addition(false);
			andrew.addition(false);
			andrew.addition(false);
			return;
		}

		for(int i = 0; i < 3; i++)
		{
			andrew.ElGamal_multiplication();
		}

		// Division Test, ElGamal	
		andrew.ElGamal_division(2);
		andrew.ElGamal_division(3);
		andrew.ElGamal_division(4);
		andrew.ElGamal_division(5);
		andrew.ElGamal_division(25);

		// Test Protocol 4 with ElGamal
		for(int i = 0; i < 16 * 3; i++)
		{
			andrew.ElGamal_Protocol4();
		}
	}


}
