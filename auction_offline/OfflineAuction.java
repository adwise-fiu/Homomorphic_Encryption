
import security.gm.GMCipher;
import security.gm.GMKeyPairGenerator;
import security.gm.GMPrivateKey;
import security.gm.GMPublicKey;
import security.misc.HomomorphicException;

import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;
import security.paillier.PaillierSignature;
import security.DGK.DGKOperations;
import security.DGK.DGKKeyPairGenerator;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.DGK.DGKSignature;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalKeyPairGenerator;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamalSignature;
import security.elgamal.ElGamal_Ciphertext;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.List;

import java.io.IOException;

public class OfflineAuction
{	
	private static int KEY_SIZE = 1024;
	
	// All Key Pairs
	private static KeyPair dgk = null;
	private static KeyPair paillier = null;
	private static KeyPair el_gamal = null;
	
	// Build DGK Keys
	private static DGKPublicKey dgk_pk = null;
	private static DGKPrivateKey dgk_sk = null;
	
	private static PaillierPublicKey pk = null;
	private static PaillierPrivateKey sk = null;

	private static ElGamalPublicKey el_pk = null;
	private static ElGamalPrivateKey el_sk = null;
	

	public static void main(String[] args) 
    		throws HomomorphicException, IOException, ClassNotFoundException 

	{
		// Build DGK Keys
		DGKKeyPairGenerator p = new DGKKeyPairGenerator();
		p.initialize(KEY_SIZE, null);
		dgk = p.generateKeyPair();
		
		dgk_pk = (DGKPublicKey) dgk.getPublic();
		dgk_sk = (DGKPrivateKey) dgk.getPrivate();	
		
		// Build Paillier Keys
		PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
		p.initialize(KEY_SIZE, null);
		paillier = pa.generateKeyPair();		
		pk = (PaillierPublicKey) paillier.getPublic();
		sk = (PaillierPrivateKey) paillier.getPrivate();
		
		// Build Additive El-Gamal Key
		ElGamalKeyPairGenerator pg = new ElGamalKeyPairGenerator();
		// NULL -> ADDITIVE
		// NOT NULL -> MULTIPLICATIVE
		pg.initialize(KEY_SIZE, null);
		el_gamal = pg.generateKeyPair();
		el_pk = (ElGamalPublicKey) el_gamal.getPublic();
		el_sk = (ElGamalPrivateKey) el_gamal.getPrivate();

		Thread andrew = new Thread(new Bob(paillier, dgk, el_gamal));
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
