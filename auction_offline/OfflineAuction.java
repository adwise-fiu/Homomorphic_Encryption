import security.paillier.PaillierKeyPairGenerator;
import security.DGK.DGKOperations;
import security.DGK.DGKKeyPairGenerator;
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
	
	public OfflineAuction(BigInteger x, BigInteger y, KeyPair paillier, KeyPair dgk)
	{
		this.x = x;
		this.y = y;
		this.paillier = paillier;
		this.dgk = dgk;
		run_compare();
	}
	
	public void run_compare()
	{
		Alice Niu = new Alice(this.x);
		Thread andrew = new Thread(new Bob(this.paillier, this.dgk, this.y));
		andrew.start();
		Thread yujia = new Thread(Niu);
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
		BigInteger a = new BigInteger("128");
		BigInteger b = new BigInteger("129");
		
		OfflineAuction auction = new OfflineAuction(a, b, paillier, dgk);
		if(auction.getResult())
		{
			System.out.println("Offline- X >= Y");
		}
		else
		{
			System.out.println("Offline - X < Y");
		}
		
		// If you need to re-use with same keys, set variables and run offline auction!
		auction.setX(new BigInteger("32"));
		auction.setY(new BigInteger("33"));
		auction.run_compare();
		if(auction.getResult())
		{
			System.out.println("Offline- X >= Y");
		}
		else
		{
			System.out.println("Offline - X < Y");
		}	
		
	}
}
