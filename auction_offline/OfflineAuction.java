import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;

import security.DGK.DGKOperations;
import security.DGK.DGKKeyPairGenerator;
import security.DGK.DGKPublicKey;

import security.socialistmillionaire.alice;
import security.socialistmillionaire.bob;
import security.misc.HomomorphicException;

import java.math.BigInteger;
import java.security.KeyPair;
import java.io.IOException;

public class OfflineAuction
{	
	private static int KEY_SIZE = 1024;
	
	// All Key Pairs
	private static KeyPair dgk = null;
	private static KeyPair paillier = null;

	private BigInteger x;
	private BigInteger y;
	
	private boolean result = false;
	private int type = -1;
	
	/*
	= 	1 	Pailler X>=1
	>= 	2	Pailler X>=Y
	>	3	DGK	X>Y
	<=	4	Pailler Y>=X
	<	5	DGK	Y>X
	*/	
	
	public OfflineAuction(BigInteger x, BigInteger y, KeyPair paillier, KeyPair dgk, int type)
	{
		if (type == 4 || type == 5) {
			this.y = x;
			this.x = y;
		}
		else {
			this.x = x;
			this.y = y;
		}
		this.paillier = paillier;
		this.dgk = dgk;
		this.type = type;
	}
	
	public void run_compare() throws HomomorphicException
	{
		if (type == 1) {
			PaillierPublicKey pk = (PaillierPublicKey) this.paillier.getPublic();
			this.y = PaillierCipher.encrypt(BigInteger.ONE, pk);
			this.x = x; 
		}
		

		Alice Niu = null;
		Bob andrew = null;
		
		if (type == 1 || type == 2 || type == 4) {
			// pick Pailler
			Niu = new Alice(this.x, false);
			andrew = new Bob(this.paillier, this.dgk, this.y, false);
		}
		else {
			// pick DGK
			Niu = new Alice(this.x, true);
			andrew = new Bob(this.paillier, this.dgk, this.y, true);
		}
		
		Thread andrew_compare = new Thread(andrew);
		andrew_compare.start();
		Thread yujia = new Thread(Niu);
		yujia.start();
		try
		{
			andrew_compare.join();
			yujia.join();
		}
		catch (InterruptedException e)
		{
			e.printStackTrace();
		}
		this.result = Niu.getResult();		
	}
	
	public boolean getResult() {
		return this.result;
	}
	
	public void setX(BigInteger x) {
		this.x = x;
	}
	
	public void setY(BigInteger y) {
		this.y = y;
	}
	
	public void setType(int type) {
		this.type = type;
	}
	
	public static void main(String[] args) 
    		throws HomomorphicException, IOException, ClassNotFoundException 

	{
		// Build DGK Keys - Should be generated once, stored in another class
		DGKKeyPairGenerator p = new DGKKeyPairGenerator();
		p.initialize(KEY_SIZE, null);
		dgk = p.generateKeyPair();		
		
		// Build Paillier Keys - Should be generated once, stored in another class
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		p.initialize(KEY_SIZE, null);
		paillier = pa.generateKeyPair();		
		
		// Create OfflineAuction and run comparisons one time as needed
		// I don't know if you want the args to already be encrypted?
		BigInteger plain_a = new BigInteger("128");
		BigInteger plain_b = new BigInteger("129");
		
		PaillierPublicKey pk = (PaillierPublicKey) paillier.getPublic();
		DGKPublicKey dgk_pk = (DGKPublicKey) dgk.getPublic();
		
		BigInteger a = PaillierCipher.encrypt(plain_a, pk);
		BigInteger b = PaillierCipher.encrypt(plain_b, pk);
		
		// PLEASE NOTE, I assume you correctly picked DGK or Paillier Encryption before putting
		// in the constructor!
		OfflineAuction auction = new OfflineAuction(a, b, paillier, dgk, 2);
		auction.run_compare();
		if(auction.getResult())
		{
			System.out.println("Offline- X >= Y");
		}
		else
		{
			System.out.println("Offline - X < Y");
		}
		
		a = DGKOperations.encrypt(plain_a, dgk_pk);
		b = DGKOperations.encrypt(plain_b, dgk_pk);
		
		// If you need to re-use with same keys, set variables and run offline auction!
		auction.setX(a);
		auction.setY(b);
		auction.setType(3);
		auction.run_compare();
		if(auction.getResult())
		{
			System.out.println("Offline- X > Y");
		}
		else
		{
			System.out.println("Offline - X <= Y");
		}	
		
	}
}
