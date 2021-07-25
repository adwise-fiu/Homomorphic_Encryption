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

public class test_bob {
	
    public static void main(String[] args) 
    		throws HomomorphicException, IOException, ClassNotFoundException 
    {
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
    		
    	bob_socket = new ServerSocket(9254);
    	bob_client = bob_socket.accept();
    	
    	// Note: Alice automatically gets the public keys!
    	andrew = new bob(bob_client, pe, DGK, el_gamal);
    	andrew.Protocol4();
    
    	// Close everything
    	bob_socket.close();
    }
	
}
