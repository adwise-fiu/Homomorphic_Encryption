package test;

import security.misc.HomomorphicException;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;
import security.socialistmillionaire.*;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class test_alice {

    public static void main(String[] args) 
    		throws HomomorphicException, IOException, ClassNotFoundException 
    {
        ObjectInputStream fromBob = null;
	ObjectOutputStream toBob = null;
	
      	// create a number
        long num2 = 64;
        BigInteger secondNumber = BigInteger.valueOf(num2);
        
        // Connect to Bob
        Socket bob_socket = new Socket("127.0.0.1", 9254);
	fromBob = new ObjectInputStream(bob_socket.getInputStream());
	toBob = new ObjectOutputStream(bob_socket.getOutputStream());
	
        alice Niu = new alice(bob_socket);
        
        // Since Bob built the key pair, and automatically hands you the public key
        // get it now from bob (bob hands it to Alice in constructor)
        // You should always use the public key bob gives you
        PaillierPublicKey pka = Niu.getPaillierPublicKey();
        BigInteger secondNumberEncrypted = PaillierCipher.encrypt(secondNumber, pka);
                
        // Read object from Bob
        Object x = fromBob.readObject();
        BigInteger firstNumberEncrypted = (BigInteger) x;

        boolean firstGreaterThanSecond = Niu.Protocol4(firstNumberEncrypted, secondNumberEncrypted);
        System.out.println(firstGreaterThanSecond);
    }
}
