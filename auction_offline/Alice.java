

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
	
	private BigInteger a;

	public Alice(BigInteger a)
	{
		this.a = a;
		System.out.println("Alice got X: " + a);
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
        		Object o = fromBob.readObject();
        		BigInteger y = (BigInteger) o; // 129
        		BigInteger x = PaillierCipher.encrypt(a, pk);// 128

			if(Niu.Protocol4(x, y))
			{
				System.out.println("X >= Y");			
			}
			else
			{
				System.out.println("X < Y");
			}
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
	
}
