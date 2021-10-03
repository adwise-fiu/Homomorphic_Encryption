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
	
	private KeyPair p;
	private KeyPair d;
	private KeyPair e;
	private BigInteger b;
	
	private boolean result = false;
	
	public Bob(KeyPair paillier, KeyPair dgk, BigInteger b)
	{
		this.p = paillier;
		this.d = dgk;
		this.b = b;
		System.out.println("Bob got Y: " + b);
	}
	
	public boolean getResult() {
		return this.result;
	}
	
	// This could would be in Bob's Main Method
	public void run() {
		try
		{
		    	ObjectInputStream fromAlice = null;
			ObjectOutputStream toAlice = null;
			
			PaillierPublicKey pk = (PaillierPublicKey) this.p.getPublic();
			BigInteger encrypted_bob = PaillierCipher.encrypt(b, pk);

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
    			
			// Run Protocol 4
			this.result = andrew.Protocol4();
			if (result)
			{
				System.out.println("X >= Y");			
			}
			else
			{
				System.out.println("X < Y");
			}

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
}
