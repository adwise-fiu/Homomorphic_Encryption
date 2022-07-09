import security.misc.HomomorphicException;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;
import security.socialistmillionaire.*;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

public class test_alice {

    public static void main(String[] args) 
    		throws HomomorphicException, IOException, ClassNotFoundException 
    {
        ObjectInputStream fromBob = null;
	ObjectOutputStream toBob = null;
	
        // Connect to Bob
        Socket bob_socket = new Socket("127.0.0.1", 9254);
	fromBob = new ObjectInputStream(bob_socket.getInputStream());
	toBob = new ObjectOutputStream(bob_socket.getOutputStream());
        alice Niu = new alice(bob_socket);
        
        // Since Bob built the key pair, and automatically hands you the public key
        // get it now from bob (bob hands it to Alice in constructor)
        // You should always use the public key bob gives you
        PaillierPublicKey pka = Niu.getPaillierPublicKey();

        // Read the highest value from Bob
        Object x = fromBob.readObject();
        BigInteger bob_bid = (BigInteger) x;

	   // Now Alice must keep bidding higher until she can bid higher than Bob.
	long current = 100;
	while(true)
	{
		BigInteger big_current = BigInteger.valueOf(current);
		BigInteger new_bid = PaillierCipher.encrypt(big_current, pka);
		// is new_bid >= bob_bid?
        	boolean win_auction = Niu.Protocol4(new_bid, bob_bid);
		if(win_auction) {
			System.out.println("Alice won the auction!");
			break;
		}
		else {
			System.out.println("Alice won the auction!");
		}
		current += 5;
	}
    }
}
