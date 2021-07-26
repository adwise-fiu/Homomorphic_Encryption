package test;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.SecureRandom;

import security.DGK.DGKKeyPairGenerator;
import security.elgamal.ElGamalKeyPairGenerator;
import security.misc.HomomorphicException;
import security.paillier.PaillierKeyPairGenerator;
import security.socialistmillionaire.bob;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.math.BigInteger;

public class test_bob {
	
    public static void main(String[] args) 
    		throws HomomorphicException, IOException, ClassNotFoundException 
    {
    	ObjectInputStream fromAlice = null;
	ObjectOutputStream toAlice = null;
    
    	ServerSocket bob_socket = null;
    	Socket bob_client = null;
    	int KEY_SIZE = 1024;
    	bob andrew = null;
    	
    	// Build all Key Pairs
    	PaillierKeyPairGenerator p = new PaillierKeyPairGenerator();
    	p.initialize(KEY_SIZE, null);
    	KeyPair pe = p.generateKeyPair();

    	DGKKeyPairGenerator d = new DGKKeyPairGenerator();
    	d.initialize(KEY_SIZE, null);
    	KeyPair DGK = d.generateKeyPair();
    	
    	ElGamalKeyPairGenerator pg = new ElGamalKeyPairGenerator();
    	pg.initialize(KEY_SIZE, new SecureRandom());
    	KeyPair el_gamal = pg.generateKeyPair();
    	
    	// Create an encrypted number to send to Alice
   	BigInteger firstNumber = BigInteger.valueOf(127);
   	BigInteger firstNumberEncrypted = PaillierCipher.encrypt(firstNumber, (PaillierPublicKey) pe.getPublic());
    	
    	// Listen until Alice connects...
    	bob_socket = new ServerSocket(9254);
    	bob_client = bob_socket.accept();

	fromAlice = new ObjectInputStream(bob_client.getInputStream());
	toAlice = new ObjectOutputStream(bob_client.getOutputStream());
    	
    	// Note: Alice automatically gets the public keys!
    	andrew = new bob(bob_client, pe, DGK, el_gamal);
    	
    	// Send the encrypted number to Alice
    	toAlice.writeObject(firstNumberEncrypted);
    	
    	andrew.Protocol4();
    
    	// Close everything
    	bob_socket.close();
    }
	
}
