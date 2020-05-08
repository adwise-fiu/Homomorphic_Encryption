package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;

import security.DGK.DGKOperations;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamal_Ciphertext;
import security.generic.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/*
Credits to Andrew Quijano and Dr. Samet Tonyali
Terms of Use:
Feel free to use this code as you like.
DGK was created in 2007 by:
Ivan Damgard, Martin Geisler, and Mikkel Kroigaard (DGK).
Title of Papers: (Source of Protocol 1, Protocol 2)
Efficient and Secure Comparison for On-Line auctions (2007)
A correction to Efficient and Secure Comparison for Online auctions (2009)
Protocol 3 and Protocol 4 was created referencing Thjis Veugen's Paper:
Improving the DGK Comparison Protocol (2012)
*/

enum Algorithm
{
    INSERT_SORT, MERGE_SORT, QUICK_SORT, BUBBLE_SORT;
}

public final class alice implements socialist_millionaires, Runnable
{
	private class Pair 
	{
		BigInteger min;
		BigInteger max;
	}
	
    // To avoid code reuse in Sorting...Flag to use Protocol 2 or Protocol 4
    private boolean USE_PROTOCOL_2 = false;
    private boolean FAST_DIVIDE = false;
    
	// Alice  will be given the Public Keys
	private PaillierPublicKey pk = null;
	private DGKPublicKey pubKey = null;
	private ElGamalPublicKey e_pk = null;

	// ONLY USED FOR DEBUGGING
	private DGKPrivateKey privKey = null;
	private PaillierPrivateKey sk = null;
	private ElGamalPrivateKey e_sk = null;
	
	// Needed for comparison
	private boolean isDGK = false;
	private BigInteger [] toSort = null;
	private BigInteger [] sortedArray = null;
	// Temporary for Merge Sort
    private BigInteger [] tempBigMerg = null;
    
	//I/O
	private ObjectOutputStream toBob = null;
	private ObjectInputStream fromBob = null;
	
	// Current Algorithm to Sort with
	private Algorithm algo;
    private final BigInteger powL;
    
    // YOU SHOULD USE THIS CONSTRUCTOR!
    public alice (Socket clientSocket) throws IOException, ClassNotFoundException
	{
    	this(clientSocket, false);
	}
	
	public alice (Socket clientSocket,
            boolean is_testing) throws IOException, ClassNotFoundException
	{
		if(clientSocket != null)
		{
			toBob = new ObjectOutputStream(clientSocket.getOutputStream());
			fromBob = new ObjectInputStream(clientSocket.getInputStream());
		}
		else
		{
			throw new NullPointerException("Client Socket is null!");
		}
		this.isDGK = false;
		this.algo = Algorithm.BUBBLE_SORT;
		
		this.receivePublicKeys();
		powL = TWO.pow(pubKey.getL());
		
		if(is_testing)
		{
			this.debug();
		}
	}
	
	// Get/Set Fast Divide/Protocol 2
	public boolean getProtocol2()
	{
		return USE_PROTOCOL_2;
	}
		
	public boolean getFastDivide()
	{
		return FAST_DIVIDE;
	}
		
	public void setFastDivide(boolean FAST_DIVIDE)
	{
		this.FAST_DIVIDE = FAST_DIVIDE;
	}
		
	public void setProtocol2(boolean USE_PROTOCOL_2)
	{
		this.USE_PROTOCOL_2 = USE_PROTOCOL_2;
	}

	public boolean isDGK()
	{
		return isDGK;
	}
	
	public void setDGKMode(boolean isDGK)
	{
		this.isDGK = isDGK;
	}
	
	public void setSorting(List<BigInteger> toSort)
	{
		this.toSort = toSort.toArray(new BigInteger[toSort.size()]);
	}
	
	public void setSorting(BigInteger [] toSort)
	{
		this.toSort = toSort;
	}
	
	public BigInteger [] getSortedArray()
	{
		return sortedArray;
	}
	
	public PaillierPublicKey getPaiilierPublicKey()
	{
		return pk;
	}
	
	public DGKPublicKey getDGKPublicKey()
	{
		return pubKey;
	}
	
	public ElGamalPublicKey getElGamalPublicKey()
	{
		return e_pk;
	}

	public boolean Protocol1(BigInteger x) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		// Constraint...
		if(x.bitLength() > pubKey.getL())
		{
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + x.bitLength() + " bits");
		}
		
		int answer = -1;
		int deltaB = -1;
		int deltaA = rnd.nextInt(2);
		Object in = null;
		BigInteger [] Encrypted_Y = null;
		BigInteger [] C = null;
		BigInteger [] XOR = null;
		//BigInteger s = null;
		
		// Step 1: Get Y bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[])
		{
			Encrypted_Y = (BigInteger []) in;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 3 Step 1: Missing Y-bits!");
		}

		if (x.bitLength() < Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ONE);
			toBob.flush();
			return true;
		}
		else if(x.bitLength() > Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ZERO);
			toBob.flush();
			return false;
		}

		// Otherwise, if bit size is equal, proceed!
		// Step 2: compute Encrypted X XOR Y
		XOR = new BigInteger[Encrypted_Y.length];
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			//Enc[x XOR y] = [y_i]
			if (NTL.bit(x, i) == 0)
			{
				XOR[i] = Encrypted_Y[i];
			}
			//Enc[x XOR y] = [1] - [y_i]
			else
			{
				XOR[i] = DGKOperations.subtract(pubKey, pubKey.ONE(), Encrypted_Y[i]);
			}
		}
	
		// Step 3: Alice picks deltaA and computes S
		//s = DGKOperations.encrypt(pubKey, 1 - 2 * deltaA);
		
		// Step 4: Compute C_i
		C = new BigInteger[Encrypted_Y.length + 1];
		
		// Compute the Product of XOR, add s and compute x - y
		// C_i = sum(XOR) + s + x_i - y_i
		
		for (int i = 0; i < Encrypted_Y.length;i++)
		{
			C[i] = DGKOperations.multiply(pubKey, DGKOperations.sum(pubKey, XOR, i), 3);
			C[i] = DGKOperations.add_plaintext(pubKey, C[i], 1 - 2 * deltaA);
			C[i] = DGKOperations.add_plaintext(pubKey, C[i], NTL.bit(x, i));
			C[i] = DGKOperations.subtract(pubKey, C[i], Encrypted_Y[i]);
		}
		
		//This is c_{-1}
		C[Encrypted_Y.length] = DGKOperations.sum(pubKey, XOR);
		C[Encrypted_Y.length] = DGKOperations.add_plaintext(pubKey, C[Encrypted_Y.length], deltaA);

		// Step 5: Blinds C_i, Shuffle it and send to Bob
		for (int i = 0; i < C.length; i++)
		{
			C[i] = DGKOperations.multiply(pubKey, C[i], rnd.nextInt(pubKey.getU().intValue()) + 1);
		}
		C = shuffle_bits(C);
		toBob.writeObject(C);
		toBob.flush();
		
		// Step 6: Bob looks for any 0's in C_i and computes DeltaB
		
		// Step 7: Obtain Delta B from Bob
		deltaB = fromBob.readInt();
		
		// 1 XOR 1 = 0 and 0 XOR 0 = 0, so X > Y
		if (deltaA == deltaB)
		{
			answer = 0;
		}
		// 1 XOR 0 = 1 and 0 XOR 1 = 1, so X <= Y
		else
		{
			answer = 1;
		}

		/*
		 * Step 8: Bob has the Private key anyways...
		 * Send him the encrypted answer!
		 * Alice and Bob know now without revealing x or y!
		 */
		toBob.writeObject(DGKOperations.encrypt(pubKey, answer));
		toBob.flush();
		return answer == 1;
	}
	
	public boolean Protocol2(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object bob = null;
		int deltaB = -1;
		int deltaA = rnd.nextInt(2);
		int x_leq_y = -1;
		int comparison = -1;
		BigInteger alpha_lt_beta = null;
		BigInteger z = null;
		BigInteger zdiv2L =  null;
		BigInteger result = null;
		BigInteger r = null;
		BigInteger alpha = null;
		
		// Step 1: 0 <= r < N
		// Pick Number of l + 1 + sigma bits
		// Considering DGK is an option, just stick with size of Zu		
		if (isDGK)
		{
			throw new IllegalArgumentException("Protocol 2 is NOT allowed with DGK! Used Protocol 4!");
		}
		else
		{
			// Generate Random Number with l + 1 + sigma bits
			if (pubKey.getL() + SIGMA + 2 < pk.keysize)
			{
				r = NTL.generateXBitRandom(pubKey.getL() + 1 + SIGMA);
			}
			else
			{
				throw new IllegalArgumentException("Invalid due to constraint: l + sigma + 2 < log_2(N)!");
			}
		}
		
		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 * [[x + 2^l + r]]
		 * [[z]] = [[x - y + 2^l + r]]
		 */
		z = PaillierCipher.add_plaintext(x, r.add(powL).mod(pk.getN()), pk);
		z = PaillierCipher.subtract(z, y, pk);
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

		// Step 3: alpha = r (mod 2^l)
		alpha = NTL.POSMOD(r, powL);

		// Step 4: Complete Protocol 1 or Protocol 3
    	boolean P3 = Protocol3(alpha, deltaA);
    	if(P3)
    	{
    		x_leq_y = 1;
    	}
    	else
    	{
    		x_leq_y = 0;
    	}
    	
    	// Step 5A: get Delta B
    	
    	
		// Step 5A: get Delta B 
    	if(deltaA == x_leq_y)
        {
            deltaB = 0;
        }
        else
        {
            deltaB = 1;
        }

		// Step 5B: Bob sends z/2^l 
		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zdiv2L = (BigInteger) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 2, Step 5: z/2^l not found!");
		}

  		// Step 6: Get [[beta < alpha]]
        if(deltaA == 1)
        {
        	alpha_lt_beta = PaillierCipher.encrypt(deltaB, pk);
        }
        else
        {
        	alpha_lt_beta = PaillierCipher.encrypt(1 - deltaB, pk);
        }
        
		// Step 7: get [[x <= y]]
        result = PaillierCipher.subtract(zdiv2L, PaillierCipher.encrypt(r.divide(powL), pk), pk);
        result = PaillierCipher.subtract(result, alpha_lt_beta, pk);
        
		/*
		 * Unofficial Step 8:
		 * Since the result is encrypted...I need to send
		 * this back to Bob (Android Phone) to decrypt the solution...
		 * 
		 * Bob by definition would know the answer as well.
		 */

		toBob.writeObject(result);
		toBob.flush();
		comparison = fromBob.readInt();// x <= y
		// IF SOMETHING HAPPENS...GET POST MORTERM HERE
		if (comparison != 0 && comparison != 1)
		{
			throw new IllegalArgumentException("Invalid Comparison output! --> " + comparison);
		}
		return comparison == 1;
	}
	
	public boolean Protocol3(BigInteger x) throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		return Protocol3(x, rnd.nextInt(2));
	}

	public boolean Protocol3_equals(BigInteger x) throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		if(x.bitLength() > pubKey.getL())
		{
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + x.bitLength() + " bits");
		}
		
		Object in = null;
		BigInteger [] XOR = null;
		BigInteger [] Encrypted_Y = null;
		//Step 1: Receive y_i bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[])
		{
			Encrypted_Y = (BigInteger []) in;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 3 Equality Step 1: Missing Y-bits!");
		}

		// Case 1, delta B is ALWAYS INITIALIZED TO 0
		// y has more bits -> y is bigger
		if (x.bitLength() != Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ZERO);
			toBob.flush();
			return false;
		}
		else
		{
			// Step 2: compute Encrypted X XOR Y
			XOR = new BigInteger[Encrypted_Y.length];
			for (int i = 0; i < Encrypted_Y.length; i++)
			{
				//Enc[x XOR y] = [y_i]
				if (NTL.bit(x, i) == 0)
				{
					XOR[i] = Encrypted_Y[i];
				}
				//Enc[x XOR y] = [1] - [y_i]
				else
				{
					XOR[i] = DGKOperations.subtract(pubKey, pubKey.ONE(), Encrypted_Y[i]);
				}
			}
			toBob.writeObject(XOR);
			toBob.flush();
			// Step 3: a XOR a = 0
			return fromBob.readInt() == 1;
		}
	}
	
	/*
	 * Input Alice: x (unencrypted BigInteger x)
	 * Input Bob: y (unencrypted BigInteger y), Private Keys
	 * 
	 * Result: [[x <= y]] or [x <= y]
	 * Alice and Bob WITHOUT revealing x, y
	 * It is boolean value! 
	 * x <= y -> [[1]]
	 * x > y -> [[0]]
	 */

	private boolean Protocol3(BigInteger x, int deltaA)
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		if(x.bitLength() > pubKey.getL())
		{
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + x.bitLength() + " bits");
		}
		
		Object in = null;
		BigInteger [] XOR = null;
		BigInteger [] C = null;
		BigInteger [] Encrypted_Y = null;
		int deltaB = -1;
		int answer = -1;

		//Step 1: Receive y_i bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[])
		{
			Encrypted_Y = (BigInteger []) in;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 3 Step 1: Missing Y-bits!");
		}

		/*
		 * Currently by design of the program
		 * 1- Alice KNOWS that bob will assume deltaB = 0.
		 *
		 * Alice knows the protocol should be skipped if
		 * the bit length is NOT equal.
		 *
		 * Case 1:
		 * y has more bits than x IMPLIES that y is bigger
		 * x <= y is 1 (true)
		 * given deltaB is 0 by default...
		 * deltaA must be 1
		 * answer = 1 XOR 0 = 1
		 *
		 * Case 2:
		 * x has more bits than x IMPLIES that x is bigger
		 * x <= y is 0 (false)
		 * given deltaB is 0 by default...
		 * deltaA must be 0
		 * answer = 0 XOR 0 = 0
		 */

		// Case 1, delta B is ALWAYS INITIALIZED TO 0
		// y has more bits -> y is bigger
		if (x.bitLength() < Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ONE);
			toBob.flush();
			// x <= y -> 1 (true)
			return true;
		}

		// Case 2 delta B is 0
		// x has more bits -> x is bigger
		else if(x.bitLength() > Encrypted_Y.length)
		{
			toBob.writeObject(BigInteger.ZERO);
			toBob.flush();
			// x <= y -> 0 (false)
			return false;
		}

		// if equal bits, proceed!
		// Step 2: compute Encrypted X XOR Y
		XOR = new BigInteger[Encrypted_Y.length];
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			//Enc[x XOR y] = [y_i]
			if (NTL.bit(x, i) == 0)
			{
				XOR[i] = Encrypted_Y[i];
			}
			//Enc[x XOR y] = [1] - [y_i]
			else
			{
				XOR[i] = DGKOperations.subtract(pubKey, pubKey.ONE(), Encrypted_Y[i]);
			}
		}
		
		// Step 3: delta A is computed on initialization, it is 0 or 1.
		
		// Step 4A: Generate C_i, see c_{-1} to test for equality!
		// Step 4B: alter C_i using Delta A
		// C_{-1} = C_i[yBits], will be computed at the end...
		C = new BigInteger [Encrypted_Y.length + 1];
			
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			C[i] = DGKOperations.sum(pubKey, XOR, Encrypted_Y.length - 1 - i);
			if (deltaA == 0)
			{
				// Step 4 = [1] - [y_i bit] + [c_i]
				// Step 4 = [c_i] - [y_i bit] + [1]
				C[i] = DGKOperations.subtract(pubKey, C[i], Encrypted_Y[Encrypted_Y.length - 1 - i]);
				C[i] = DGKOperations.add_plaintext(pubKey, C[i], 1);
			}
			else
			{
				// Step 4 = [y_i] + [c_i]
				C[i]= DGKOperations.add(pubKey, C[i], Encrypted_Y[Encrypted_Y.length - 1 - i]);
			}
		}
		
		// This is c_{-1}
		C[Encrypted_Y.length] = DGKOperations.sum(pubKey, XOR);
		C[Encrypted_Y.length] = DGKOperations.add_plaintext(pubKey, C[Encrypted_Y.length], deltaA);

		// Step 5: Apply the Blinding to C_i and send it to Bob
		for (int i = 0; i < Encrypted_Y.length; i++)
		{
			// if i is NOT in L, just place a random NON-ZERO
			if(NTL.bit(x, i) != deltaA)
			{
				C[Encrypted_Y.length - 1 - i] = DGKOperations.encrypt(pubKey, rnd.nextInt(pubKey.getL()) + 1);
			}
		}
		// Blind and Shuffle bits!
		C = shuffle_bits(C);
		for (int i = 0; i < C.length; i++)
		{
			C[i] = DGKOperations.multiply(pubKey, C[i], rnd.nextInt(pubKey.getL()) + 1);
		}
		toBob.writeObject(C);
		toBob.flush();

		// Step 7: Obtain Delta B from Bob
		deltaB = fromBob.readInt();

		// 1 XOR 1 = 0 and 0 XOR 0 = 0, so X > Y
		if (deltaA == deltaB)
		{
			answer = 0;
		}
		// 1 XOR 0 = 1 and 0 XOR 1 = 1, so X <= Y
		else
		{
			answer = 1;
		}

		/*
		 * Step 8: Bob has the Private key anyways...
		 * Send him the encrypted answer!
		 * Alice and Bob know now without revealing x or y!
		 */
		toBob.writeObject(DGKOperations.encrypt(pubKey, BigInteger.valueOf(answer)));
		toBob.flush();
		return answer == 1;
	}
	
	// USED ONLY AS PROTOCOL 3 REPLACEMENT!
	// WOrks 100% reliably only in DGK Mode as N can skew things a bit, 
	// especially since I am only using for private comparison NOT sub-protocol
	public boolean Modified_Protocol3(BigInteger r)
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		BigInteger alpha = null;
		boolean answer;
		// Constraint...
		if(r.bitLength() > pubKey.getL())
		{
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + r.bitLength() + " bits");
		}
		if(isDGK)
		{
			alpha = r.mod(powL);
			answer = Modified_Protocol3(alpha, r, rnd.nextInt(2));
		}
		else
		{
			isDGK = true;
			alpha = r.mod(powL);
			answer = Modified_Protocol3(alpha, r, rnd.nextInt(2));
			isDGK = false;
		}
		return answer;
	}
	
	// Modified Protocol 3 for Protocol 4
	// This should mostly use ONLY DGK stuff!
	private boolean Modified_Protocol3(BigInteger alpha, BigInteger r, int deltaA) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		int answer = -1;
		Object in = null;
		BigInteger [] beta_bits = null;
		BigInteger [] encAlphaXORBeta = null;
		BigInteger [] w = null;
		BigInteger [] C = null;
		BigInteger alpha_hat = null;
		BigInteger d = null;
		BigInteger N = null;
		long exponent;
		
		// Get N from size of Plain-text space
		if(isDGK)
		{
			N = pubKey.getU();
		}
		else
		{
			N = pk.getN();
		}
		
		// Step A: get d from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger)
		{
			d = (BigInteger) in;
		}
		else
		{
			throw new IllegalArgumentException("BigInteger: d not found!");
		}
		
		// Step B: get beta_bits from Bob
		in = fromBob.readObject();
		if (in instanceof BigInteger[])
		{
			beta_bits = (BigInteger []) in;
		}
		else
		{
			throw new IllegalArgumentException("BigInteger []: C not found!");
		}
		
		/*
		 * Currently by design of the program
		 * 1- Alice KNOWS that bob will assume deltaB = 0.
		 *
		 * Alice knows the protocol should be skipped if
		 * the bit length is NOT equal.
		 *
		 * Case 1:
		 * y has more bits than x IMPLIES that y is bigger
		 * x <= y is 1 (true)
		 * given deltaB is 0 by default...
		 * deltaA must be 1
		 * answer = 1 XOR 0 = 1
		 *
		 * Case 2:
		 * x has more bits than x IMPLIES that x is bigger
		 * x <= y is 0 (false)
		 * given deltaB is 0 by default...
		 * deltaA must be 0
		 * answer = 0 XOR 0 = 0
		 */

		if (alpha.bitLength() < beta_bits.length)
		{
			toBob.writeObject(BigInteger.ONE);
			toBob.flush();
			return true;
		}
		else if(alpha.bitLength() > beta_bits.length)
		{
			toBob.writeObject(BigInteger.ZERO);
			toBob.flush();
			return false;
		}
		
		// Step C: Alice corrects d...
		if(r.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) == -1)
		{
			d = DGKOperations.encrypt(pubKey, BigInteger.ZERO);
		}
		
		// Step D: Compute alpha_bits XOR beta_bits
		encAlphaXORBeta = new BigInteger[beta_bits.length];
		for (int i = 0; i < encAlphaXORBeta.length; i++)
		{
			//Enc[x XOR y] = [y_i]
			if (NTL.bit(alpha, i) == 0)
			{
				encAlphaXORBeta[i] = beta_bits[i];
			}
			//Enc[x XOR y] = [1] - [y_i]
			else
			{
				encAlphaXORBeta[i] = DGKOperations.subtract(pubKey, pubKey.ONE(), beta_bits[i]);				
			}
		}
		
		// Step E: Compute Alpha Hat
		alpha_hat = r.subtract(N).mod(powL);
		w = new BigInteger[beta_bits.length];
		
		for (int i = 0; i < beta_bits.length;i++)
		{
			if(NTL.bit(alpha_hat, i) == NTL.bit(alpha, i))
			{
				w[i] = encAlphaXORBeta[i];
			}
			else
			{
				w[i] = DGKOperations.subtract(pubKey, encAlphaXORBeta[i], d);
			}
		}
		
		// Step F: See Optimization 1
		for (int i = 0; i < beta_bits.length;i++)
		{
			// If it is 16 or 32 bits...
			if(pubKey.getL() % 16 == 0)
			{
				if(NTL.bit(alpha_hat, i) == NTL.bit(alpha, i))
				{
					w[i] = DGKOperations.multiply(pubKey, w[i], pubKey.getL());	
				}
			}
			else
			{
				if(NTL.bit(alpha_hat, i) == NTL.bit(alpha, i))
				{
					w[i] = DGKOperations.multiply(pubKey, w[i], powL);	
				}
			}
		}
		
		// Step G: Delta A computed at start!

		// Step H: See Optimization 2
		C = new BigInteger[beta_bits.length + 1];
		for (int i = 0; i < beta_bits.length;i++)
		{
			if(deltaA != NTL.bit(alpha, i) && deltaA != NTL.bit(alpha_hat, i))
			{
				// C[i] = DGKOperations.encrypt(pubKey, NTL.RandomBnd(pubKey.getU()));
				// Blinding should take care of the rest!
				C[i] = pubKey.ONE();
			}
			else
			{
				exponent = NTL.bit(alpha_hat, i) - NTL.bit(alpha, i);
				C[i] = DGKOperations.multiply(pubKey, DGKOperations.sum(pubKey, w, i), 3);
				C[i] = DGKOperations.add_plaintext(pubKey, C[i], 1 - (2* deltaA));
				C[i] = DGKOperations.add_plaintext(pubKey, C[i], NTL.bit(alpha, i));
				C[i] = DGKOperations.add(pubKey, C[i], DGKOperations.multiply(pubKey, d, exponent));
				C[i] = DGKOperations.subtract(pubKey, C[i], beta_bits[i]);
			}
		}
		
		//This is c_{-1}
		C[beta_bits.length] = DGKOperations.sum(pubKey, encAlphaXORBeta);
		C[beta_bits.length] = DGKOperations.add_plaintext(pubKey, C[beta_bits.length], deltaA);

		// Step I: SHUFFLE BITS AND BLIND WITH EXPONENT
		C = shuffle_bits(C);
		for (int i = 0; i < C.length; i++)
		{
			C[i] = DGKOperations.multiply(pubKey, C[i], rnd.nextInt(pubKey.getU().intValue()) + 1);
		}
		toBob.writeObject(C);
		toBob.flush();
		
		// Step J: Bob checks whether a C_i has a zero or not...get delta B.
		int deltaB = fromBob.readInt();
		if (deltaA == deltaB)
		{
			answer = 0;
		}
		else
		{
			answer = 1;
		}
		toBob.writeObject(DGKOperations.encrypt(pubKey, answer));
		toBob.flush();
		return answer == 1;
	}
	
	public boolean Protocol4(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		int deltaB = -1;
		int x_leq_y = -1;
		int comparison = -1;
		int deltaA = rnd.nextInt(2);
		Object bob = null;
		BigInteger alpha_lt_beta = null;
		BigInteger z = null;
		BigInteger zeta_one = null;
		BigInteger zeta_two = null;
		BigInteger result = null;
		BigInteger r = null;
		BigInteger alpha = null;
		BigInteger N = null;
		
		/*
		 * Step 1: 0 <= r < N
		 * N is the Paillier plain text space, which is 1024-bits usually
		 * u is the DGK plain text space, which is l bits
		 * 
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 * [[x + 2^l + r]]
		 * [[z]] = [[x - y + 2^l + r]]
		 */
		if (isDGK)
		{
			r = NTL.RandomBnd(pubKey.getU());
			z = DGKOperations.add_plaintext(pubKey, x, r.add(powL).mod(pubKey.getU()));
			z = DGKOperations.subtract(pubKey, z, y);
			N = pubKey.getU();
		}
		else
		{
			r = NTL.RandomBnd(pk.getN());
			z = PaillierCipher.add_plaintext(x, r.add(powL).mod(pk.getN()), pk);
            z = PaillierCipher.subtract(z, y, pk);
            N = pk.getN();
		}
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

		// Step 3: alpha = r (mod 2^l)
		alpha = NTL.POSMOD(r, powL);

		// Step 4: Modified Protocol 3 or Protocol 3
		
		// See Optimization 3: true --> Use Modified Protocol 3 	
		if(r.add(TWO.pow(pubKey.getL() + 1)).compareTo(N) == -1)
		{
			toBob.writeBoolean(false);
			toBob.flush();
			if(Protocol3(alpha, deltaA))
			{
				x_leq_y = 1;
			}
			else
			{
				x_leq_y = 0;
			}
		}
		else
		{
			toBob.writeBoolean(true);
			toBob.flush();
			if(Modified_Protocol3(alpha, r, deltaA))
			{
				x_leq_y = 1;
			}
			else
			{
				x_leq_y = 0;
			}
		}
        
		// Step 5: get Delta B and [[z_1]] and [[z_2]]
    	if(deltaA == x_leq_y)
        {
            deltaB = 0;
        }
        else
        {
            deltaB = 1;
        }

		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zeta_one = (BigInteger) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 2, Step 5: BigInteger z_1 not found!");
		}
		
		bob = fromBob.readObject();
		if (bob instanceof BigInteger)
		{
			zeta_two = (BigInteger) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 2, Step 5: BigInteger z_2 not found!");
		}
		
		// Step 6: Compute [[beta <= alpha]]
		if(isDGK)
		{
			if(deltaA == 1)
			{
				alpha_lt_beta = DGKOperations.encrypt(pubKey, deltaB);
			}
			else
			{
				alpha_lt_beta = DGKOperations.encrypt(pubKey, 1 - deltaB);
			}
			
			// Step 7: Compute [[x <= y]]
			if(r.compareTo(pubKey.getU().subtract(BigInteger.ONE).divide(TWO)) == -1)
			{
				result = DGKOperations.subtract(pubKey, zeta_one, DGKOperations.encrypt(pubKey, r.divide(powL)));
				result = DGKOperations.subtract(pubKey, result, alpha_lt_beta);
			}
			else
			{
				result = DGKOperations.subtract(pubKey, zeta_two, DGKOperations.encrypt(pubKey, r.divide(powL)));
				result = DGKOperations.subtract(pubKey, result, alpha_lt_beta);
			}	
		}
		else
		{
			if(deltaA == 1)
			{
				alpha_lt_beta = PaillierCipher.encrypt(deltaB, pk);
			}
			else
			{
				alpha_lt_beta = PaillierCipher.encrypt(1 - deltaB, pk);
			}

			// Step 7: Compute [[x <= y]]
			if(r.compareTo(pk.getN().subtract(BigInteger.ONE).divide(TWO)) == -1)
			{
				result = PaillierCipher.subtract(zeta_one, PaillierCipher.encrypt(r.divide(powL), pk), pk);
				result = PaillierCipher.subtract(result, alpha_lt_beta, pk);
			}
			else
			{
				result = PaillierCipher.subtract(zeta_two, PaillierCipher.encrypt(r.divide(powL), pk), pk);
				result = PaillierCipher.subtract(result, alpha_lt_beta, pk);
			}
		}
		
		/*
		 * Unofficial Step 8:
		 * Since the result is encrypted...I need to send
		 * this back to Bob (Android Phone) to decrypt the solution...
		 * 
		 * Bob by definition would know the answer as well.
		 */

		toBob.writeObject(result);
		comparison = fromBob.readInt();// x <= y
		// IF SOMETHING HAPPENS...GET POST MORTERM HERE
		if (comparison != 0 && comparison != 1)
		{
			throw new IllegalArgumentException("Invalid Comparison result --> " + comparison);
		}
		return comparison == 1;
	}
	
	public boolean Protocol4(ElGamal_Ciphertext x, ElGamal_Ciphertext y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		int deltaB = -1;
		int x_leq_y = -1;
		int comparison = -1;
		int deltaA = rnd.nextInt(2);
		Object bob = null;
		ElGamal_Ciphertext alpha_lt_beta = null;
		ElGamal_Ciphertext z = null;
		ElGamal_Ciphertext zeta_one = null;
		ElGamal_Ciphertext zeta_two = null;
		ElGamal_Ciphertext result = null;
		BigInteger r = null;
		BigInteger alpha = null;
		BigInteger N = e_pk.getP().subtract(BigInteger.ONE);
		
		// Step 1: 0 <= r < N
		r = NTL.RandomBnd(e_pk.FIELD_SIZE);
		
		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 * [[x + 2^l + r]]
		 * [[z]] = [[x - y + 2^l + r]]
		 */
		z = ElGamalCipher.add(x, ElGamalCipher.encrypt(e_pk, r.add(powL)), e_pk);
		z = ElGamalCipher.subtract(z, y, e_pk);
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

		// Step 3: alpha = r (mod 2^l)
		alpha = NTL.POSMOD(r, powL);

		// Step 4: Modified Protocol 3 or Protocol 3
		
		// See Optimization 3: true --> Use Modified Protocol 3 	
		if(r.add(TWO.pow(pubKey.getL() + 1)).compareTo(N) == -1)
		{
			toBob.writeBoolean(false);
			toBob.flush();
			if(Protocol3(alpha, deltaA))
			{
				x_leq_y = 1;
			}
			else
			{
				x_leq_y = 0;
			}
		}
		else
		{
			toBob.writeBoolean(true);
			toBob.flush();
			if(Modified_Protocol3(alpha, r, deltaA))
			{
				x_leq_y = 1;
			}
			else
			{
				x_leq_y = 0;
			}
		}
        
		// Step 5: get Delta B and [[z_1]] and [[z_2]]
    	if(deltaA == x_leq_y)
        {
            deltaB = 0;
        }
        else
        {
            deltaB = 1;
        }

		bob = fromBob.readObject();
		if (bob instanceof ElGamal_Ciphertext)
		{
			zeta_one = (ElGamal_Ciphertext) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_1 not found!");
		}
		
		bob = fromBob.readObject();
		if (bob instanceof ElGamal_Ciphertext)
		{
			zeta_two = (ElGamal_Ciphertext) bob;
		}
		else
		{
			throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_2 not found!");
		}
		
		// Step 6: Compute [[beta <= alpha]]
		if(deltaA == 1)
		{
			alpha_lt_beta = ElGamalCipher.encrypt(e_pk, deltaB);
		}
		else
		{
			alpha_lt_beta = ElGamalCipher.encrypt(e_pk, 1 - deltaB);
		}

		// Step 7: Compute [[x <= y]]
		if(r.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) == -1)
		{
			result = ElGamalCipher.subtract(zeta_one, ElGamalCipher.encrypt(e_pk, r.divide(powL)), e_pk);
		}
		else
		{
			result = ElGamalCipher.subtract(zeta_two, ElGamalCipher.encrypt(e_pk, r.divide(powL)), e_pk);
		}
		result = ElGamalCipher.subtract(result, alpha_lt_beta, e_pk);
		
		/*
		 * Unofficial Step 8:
		 * Since the result is encrypted...I need to send
		 * this back to Bob (Android Phone) to decrypt the solution...
		 * 
		 * Bob by definition would know the answer as well.
		 */

		toBob.writeObject(result);
		toBob.flush();
		comparison = fromBob.readInt();
		// IF SOMETHING HAPPENS...GET POST MORTERM HERE
		if (comparison != 0 && comparison != 1)
		{
			throw new IllegalArgumentException("Invalid Comparison result --> " + comparison);
			//System.out.println("Invalid Comparison result --> " + comparison);
		}
		return comparison == 1;
	}
	
	/*
	 * See Protocol 2:
	 * Encrypted Integer Division by
	 * Thjis Veugen
	 * 
	 * Input Alice: [x] and d
	 * Input Bob: d, and Private Key K
	 * Output Alice: [x/d]
	 * Constraints: 0 <= x <= N * 2^{-sigma} and 0 <= d < N
	 */
	
	// TODO: Patch to support x being (0, N]
	public BigInteger division(BigInteger x, long d) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		/*
		if(isDGK)
		{
			if(x.signum() == -1)
			{
				throw new IllegalArgumentException("Constrain violated: 0 <= x < N * 2^{-sigma}");
			}
			if(BigInteger.valueOf(d).compareTo(pubKey.bigU) >= 0 || d == 0)
			{
				throw new IllegalArgumentException("Constraint violated: 0 < d < N");
			}
		}
		else
		{
			if(x.signum() == -1 || x.compareTo(pk.n.divide(TWO.pow(SIGMA))) >= 0)
			{
				throw new IllegalArgumentException("Constrain violated: 0 <= x < N * 2^{-sigma}");
			}
			if(BigInteger.valueOf(d).compareTo(pk.n) >= 0 || d == 0)
			{
				throw new IllegalArgumentException("Constraint violated: 0 < d < N");
			}
		}
		*/
		Object in = null;
		BigInteger answer = null;
		BigInteger c = null;
		BigInteger z = null;
		BigInteger r = null;
		//BigInteger N = null;
		int t = 0;
		
		// Step 1
		if(isDGK)
		{
			r = NTL.generateXBitRandom(pubKey.getL() - 1).mod(pubKey.getU());
			z = DGKOperations.add_plaintext(pubKey, x, r);
			//N = pubKey.bigU;
		}
		else
		{
			r = NTL.generateXBitRandom(pk.keysize - 1).mod(pk.getN());
			z = PaillierCipher.add_plaintext(x, r, pk);
			//N = pk.n;
		}
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Executed by Bob
		
		// Step 3: Compute secure comparison Protocol
		if(!FAST_DIVIDE)
		{
			//FLIP IT
			if(Protocol3(r.mod(BigInteger.valueOf(d))))
			{
				t = 0;
			}
			else
			{
				t = 1;
			}
		}
		
		// MAYBE IF OVERFLOW HAPPENS?
		//t -= Modified_Protocol3(r.mod(powL), r, rnd.nextInt(2));
		
		// Step 4: Bob computes c and Alice receives it
		in = fromBob.readObject();
		if (in instanceof BigInteger)
		{
			c = (BigInteger) in;
		}
		else
		{
			throw new IllegalArgumentException("Division: c is not found!");
		}
		
		// Step 5: Alice computes [x/d]
		// [[z/d - r/d]]
		// [[z/d - r/d - t]]
		if (isDGK)
		{
			answer = DGKOperations.subtract(pubKey, c, DGKOperations.encrypt(pubKey, r.divide(BigInteger.valueOf(d))));
			if(t == 1)
			{
				answer = DGKOperations.subtract(pubKey, answer, DGKOperations.encrypt(pubKey, t));
			}
			// Print Answer to verify
			if(privKey != null)
			{
				System.out.println("answer: " + DGKOperations.decrypt(privKey, answer));	
			}
		}
		else
		{
			answer = PaillierCipher.subtract(c, PaillierCipher.encrypt(r.divide(BigInteger.valueOf(d)), pk), pk);
			if(t == 1)
			{
				answer = PaillierCipher.subtract(answer, PaillierCipher.encrypt(BigInteger.valueOf(t), pk), pk);
			}
			// Print Answer to verify
			if (sk != null)
			{
				System.out.println("answer: " + PaillierCipher.decrypt(answer, sk));	
			}
		}
		return answer;
	}
	
	public BigInteger multiplication(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in = null;
		BigInteger x_prime = null;
		BigInteger y_prime = null;
		BigInteger a = null;
		BigInteger b = null;
		BigInteger result = null;
		
		// Step 1
		if(isDGK)
		{
			a = NTL.RandomBnd(pubKey.getU());
			b = NTL.RandomBnd(pubKey.getU());
			x_prime = DGKOperations.add_plaintext(pubKey, x, a);
			y_prime = DGKOperations.add_plaintext(pubKey, y, b);
		}
		else
		{
			a = NTL.RandomBnd(pk.getN());
			b = NTL.RandomBnd(pk.getN());
			x_prime = PaillierCipher.add_plaintext(x, a, pk);
			y_prime = PaillierCipher.add_plaintext(y, b, pk);
		}
		toBob.writeObject(x_prime);
		toBob.flush();
		
		toBob.writeObject(y_prime);
		toBob.flush();
		
		// Step 2
		
		// Step 3
		in = fromBob.readObject();
		if (in instanceof BigInteger)
		{
			result = (BigInteger) in;
			if(isDGK)
			{
				result = DGKOperations.subtract(pubKey, result, DGKOperations.multiply(pubKey, x, b));
				result = DGKOperations.subtract(pubKey, result, DGKOperations.multiply(pubKey, y, a));
				// To avoid throwing an exception to myself of encrypt range [0, U), mod it now!
				result = DGKOperations.subtract(pubKey, result, DGKOperations.encrypt(pubKey, a.multiply(b).mod(pubKey.getU())));	
				// Debug...
				if(privKey != null)
				{
					System.out.println(DGKOperations.decrypt(result, privKey));
				}
			}
			else
			{
				result = PaillierCipher.subtract(result, PaillierCipher.multiply(x, b, pk), pk);
				result = PaillierCipher.subtract(result, PaillierCipher.multiply(y, a, pk), pk);
				// To avoid throwing an exception to myself of encrypt range [0, N), mod it now!
				result = PaillierCipher.subtract(result, PaillierCipher.encrypt(a.multiply(b).mod(pk.getN()), pk), pk);
				// Debug...
				if(sk != null)
				{
					System.out.println(PaillierCipher.decrypt(result, sk));
				}
			}
		}
		else
		{
			throw new IllegalArgumentException("Didn't get [[x' * y']] from Bob");
		}
		return result;
	}
	
	public ElGamal_Ciphertext division(ElGamal_Ciphertext x, long d) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in = null;
		ElGamal_Ciphertext answer = null;
		ElGamal_Ciphertext c = null;
		ElGamal_Ciphertext z = null;
		BigInteger r = null;
		int t = 0;
		
		// Step 1
		r = NTL.generateXBitRandom(16 - 1);
		z = ElGamalCipher.add(x, ElGamalCipher.encrypt(e_pk, r), e_pk);
		toBob.writeObject(z);
		toBob.flush();
		
		// Step 2: Executed by Bob
		
		// Step 3: Compute secure comparison Protocol 
		if(!FAST_DIVIDE)
		{
			// FLIP IT
			if(Protocol3(r.mod(BigInteger.valueOf(d))))
			{
				t = 0;
			}
			else
			{
				t = 1;
			}
		}
		
		// Step 4: Bob computes c and Alice receives it
		in = fromBob.readObject();
		if (in instanceof ElGamal_Ciphertext)
		{
			c = (ElGamal_Ciphertext) in;
		}
		else
		{
			throw new IllegalArgumentException("Alice: BigInteger not found! " + in.getClass());
		}
		
		// Step 5: Alice computes [x/d]
		// [[z/d - r/d]]
		// [[z/d - r/d - t]]
		answer = ElGamalCipher.subtract(c, ElGamalCipher.encrypt(e_pk, r.divide(BigInteger.valueOf(d))), e_pk);
		if(t == 1)
		{
			answer = ElGamalCipher.subtract(answer, ElGamalCipher.encrypt(e_pk, t), e_pk);
		}
		
		// Print Answer to verify
		if (e_sk != null)
		{
			System.out.println("answer: " + ElGamalCipher.decrypt(e_sk, answer));	
		}
		return answer;
	}
	
	public ElGamal_Ciphertext multiplication(ElGamal_Ciphertext x, ElGamal_Ciphertext y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in = null;
		ElGamal_Ciphertext result = null;
		ElGamal_Ciphertext x_prime = null;
		ElGamal_Ciphertext y_prime = null;
		BigInteger a = null;
		BigInteger b = null;
		BigInteger N = e_pk.FIELD_SIZE;
		
		// Step 1
		a = NTL.RandomBnd(N);
		b = NTL.RandomBnd(N);
		x_prime = ElGamalCipher.add(x, ElGamalCipher.encrypt(e_pk, a), e_pk);
		y_prime = ElGamalCipher.add(y, ElGamalCipher.encrypt(e_pk, b), e_pk);
		toBob.writeObject(x_prime);
		toBob.flush();
		
		toBob.writeObject(y_prime);
		toBob.flush();
		
		// Step 2
		
		// Step 3
		in = fromBob.readObject();
		if (in instanceof ElGamal_Ciphertext)
		{
			result = (ElGamal_Ciphertext) in;
			result = ElGamalCipher.subtract(result, ElGamalCipher.multiply(x, b, e_pk), e_pk);
			result = ElGamalCipher.subtract(result, ElGamalCipher.multiply(y, a, e_pk), e_pk);
			result = ElGamalCipher.subtract(result, ElGamalCipher.encrypt(e_pk, a.multiply(b)), e_pk);
			// Debug...
			if(e_sk != null)
			{
				try
				{
					System.out.println(ElGamalCipher.decrypt(e_sk, result));
				}
				catch(IllegalArgumentException e)
				{
					System.out.println("[[x * y]] is out of scope of plain-text!");
				}
			}
		}
		else
		{
			throw new IllegalArgumentException("Didn't get [[x' * y']] from Bob");
		}
		return result;
	}


	/*
	 * Purpose of Method: 
	 * Input:
	 * An Array list of Encrypted Paillier Values and Socket to Bob (KeyMaster)
	 * 
	 * What it does:
	 * It will find the index of the smallest encrypted value.
	 * This is to avoid having to consistently make deep copies/keep track of index...
	 * It will be assumed Alice can build a new sorted array list with the index.
	 * 
	 * This will use Protocol 2/Protocol 3
	 */
	
	// https://www.geeksforgeeks.org/maximum-and-minimum-in-an-array/
	// NOTE; THIS DOES NOT TURN OF BOB!!!
	private Pair getMinMax(List<BigInteger> arr) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		boolean activation = false;
		Pair results = new Pair();   
		int i;

		/* If array has even number of elements then 
		 * initialize the first two elements as minimum and 
		 * maximum */

		if (arr.size() % 2 == 0)
		{
			toBob.writeBoolean(true);
			toBob.flush();
			if(USE_PROTOCOL_2)
			{
				activation = Protocol2(arr.get(0), arr.get(1));	
			}
			else
			{
				activation = Protocol4(arr.get(0), arr.get(1));
			}
			
			if (activation)
			{
				results.max = arr.get(0);
				results.min = arr.get(1);
			}
			else
			{
				results.min = arr.get(0);
				results.max = arr.get(1);
			}
			i = 2;  /* set the starting index for loop */
		}

		/* If array has odd number of elements then 
			    initialize the first element as minimum and 
			    maximum */
		else
		{
			results.min = arr.get(0);
			results.max = arr.get(0);
			i = 1;  /* set the starting index for loop */
		}

		/* In the while loop, pick elements in pair and 
			     compare the pair with max and min so far */
		while (i < arr.size() - 1)
		{
			toBob.writeBoolean(true);
			toBob.flush();
			if(USE_PROTOCOL_2)
			{
				activation = Protocol2(arr.get(i), arr.get(i + 1));
			}
			else
			{
				activation = Protocol4(arr.get(i), arr.get(i + 1));
			}
			if (activation)
			{
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = Protocol2(arr.get(i), results.max);
				}
				else
				{
					activation = Protocol4(arr.get(i), results.max);
				}
				if(activation)
				{
					results.max = arr.get(i);
				}
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = Protocol2(arr.get(i + 1), results.min);
				}
				else
				{
					activation = Protocol4(arr.get(i + 1), results.min);
				}
				if(!activation)
				{
					results.min = arr.get(i + 1);
				}
			}
			else        
			{
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = Protocol2(arr.get(i + 1), results.max);
				}
				else
				{
					activation = Protocol4(arr.get(i + 1), results.max);
				}
				if (activation) 
				{
					results.max = arr.get(i + 1);
				}
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = Protocol2(arr.get(i), results.min);
				}
				else
				{
					activation = Protocol4(arr.get(i), results.min);
				}
				if (!activation)
				{
					results.min = arr.get(i);
				}
			}
			i += 2; /* Increment the index by 2 as two elements are processed in loop */
		}
		return results;
	}

	// https://www.geeksforgeeks.org/maximum-and-minimum-in-an-array/
	// NOTE; THIS DOES NOT TURN OF BOB!!!
	private Pair getMinMax(BigInteger [] arr) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		Pair results = new Pair();   
		int i;
		boolean activation = false;

		/* If array has even number of elements then 
		 * initialize the first two elements as minimum and 
		 * maximum */
		if (arr.length % 2 == 0)
		{
			toBob.writeBoolean(true);
			toBob.flush();
			if(USE_PROTOCOL_2)
			{
				activation = Protocol2(arr[0], arr[1]);	
			}
			else
			{
				activation = Protocol4(arr[0], arr[1]);
			}
			if (activation)     
			{
				results.max = arr[0];
				results.min = arr[1];
			}
			else
			{
				results.min = arr[0];
				results.max = arr[1];
			}
			i = 2;  /* set the starting index for loop */
		}

		/* If array has odd number of elements then 
		    initialize the first element as minimum and 
		    maximum */
		else
		{
			results.min = arr[0];
			results.max = arr[0];
			i = 1;  /* set the starting index for loop */
		}

		/* In the while loop, pick elements in pair and 
		     compare the pair with max and min so far */
	
		while (i < arr.length - 1)
		{
			toBob.writeBoolean(true);
			toBob.flush();
			if(USE_PROTOCOL_2)
			{
				activation = Protocol2(arr[i], arr[i + 1]);
			}
			else
			{
				activation = Protocol4(arr[i], arr[i + 1]);
			}
			if (activation)
			{
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = Protocol2(arr[i], results.max);
				}
				else
				{
					activation = Protocol4(arr[i], results.max);
				}
				if(activation)
				{
					results.max = arr[i];
				}
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = Protocol2(arr[i + 1], results.min);
				}
				else
				{
					activation = Protocol4(arr[i + 1], results.min);
				}
				if(!activation)
				{
					results.min = arr[i + 1];
				}
			} 
			else        
			{
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = Protocol2(arr[i + 1], results.max);
				}
				else
				{
					activation = Protocol4(arr[i + 1], results.max);
				}
				if (activation) 
				{
					results.max = arr[i + 1];
				}
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = Protocol2(arr[i], results.min);
				}
				else
				{
					activation = Protocol4(arr[i], results.min);
				}
				if (!activation)
				{
					results.min = arr[i];
				}
			}
			i += 2; /* Increment the index by 2 as two elements are processed in loop */
		}      
		return results;
	}

	// To sort an array of encrypted numbers
	public void sortArray() 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		Pair res;
		
		System.out.println("Sorting Initialized!");
		if(toSort == null)
		{
			sortedArray = null;
			return;
		}
		if(toSort.length == 1 || toSort.length == 0)
		{
			sortedArray = deep_copy(toSort);
			//sortedArray = toSort;
			return;
		}
		// deep copy already taken care of
		else if (toSort.length == 2)
		{
			res = getMinMax(toSort);
			sortedArray = new BigInteger[2];
			sortedArray[0] = res.min;
			sortedArray[1] = res.max;
			toBob.writeBoolean(false);
			toBob.flush();
			return;
		}
		
		switch(algo)
		{
			case INSERT_SORT:
				List<BigInteger> Sort = new ArrayList<BigInteger>(Arrays.asList(toSort));
				Deque<BigInteger> minSorted = new LinkedList<>();
				Deque<BigInteger> maxSorted = new LinkedList<>();
			
				// Since I am getting two a time...be careful
				// of odd sized arrays!
				if(Sort.size() % 2 == 1)
				{
					BigInteger min = getMinMax(Sort).min;
					minSorted.addFirst(min);
					Sort.remove(min);
				}
				
				while(!Sort.isEmpty())
				{
					res = getMinMax(Sort);
					minSorted.addLast(res.min);
					maxSorted.addLast(res.max);
					Sort.remove(res.max);
					Sort.remove(res.min);
				}
				
				// Merge both dequeues!
				for(Iterator<BigInteger> itr = maxSorted.descendingIterator();itr.hasNext();)
				{
					minSorted.addLast((BigInteger) itr.next());
				}
				sortedArray = minSorted.toArray(new BigInteger[minSorted.size()]);
				break;
				
			case MERGE_SORT:
				sortedArray = deep_copy(toSort);
				//sortedArray = toSort;
				this.doMergeSort(0, sortedArray.length - 1);
				break;
		        
			case QUICK_SORT:	
				sortedArray = deep_copy(toSort);
				//sortedArray = toSort;
				this.sort(sortedArray, 0, sortedArray.length - 1);
				break;
				
			case BUBBLE_SORT:
				sortedArray = deep_copy(toSort);
				//sortedArray = toSort;
				this.bubbleSort(sortedArray);
				break;
			
			default:
				System.out.println("NO SORTING ALGORITHM SELECTED!");
				break;
		}
        // Time to end Bob's while loop for Protocol2()
        toBob.writeBoolean(false);
        toBob.flush();
	}

	public void receivePublicKeys() 
			throws IOException, ClassNotFoundException
	{
		Object x = null;
		x = fromBob.readObject();
		if (x instanceof DGKPublicKey)
		{
			pubKey = (DGKPublicKey) x;
		}
		else
		{
			pubKey = null;
		}
		
		x = fromBob.readObject();
		if(x instanceof PaillierPublicKey)
		{
			pk = (PaillierPublicKey) x;
		}
		else
		{
			pk = null;
		}
	
		x = fromBob.readObject();
		if(x instanceof ElGamalPublicKey)
		{
			e_pk = (ElGamalPublicKey) x;
		}
		else
		{
			e_pk = null;
		}
	}
	
	protected void debug() throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		Object in;
		in = fromBob.readObject();
		if (in instanceof DGKPrivateKey)
		{
			privKey = (DGKPrivateKey) in;
		}
		else
		{
			throw new IllegalArgumentException("Invalid, did not receive DGK Private Key!");
		}
		in = fromBob.readObject();
		if (in instanceof PaillierPrivateKey)
		{
			sk = (PaillierPrivateKey) in;
		}
		else
		{
			throw new IllegalArgumentException("Invalid, did not receive Paillier Private Key!");
		}
		in = fromBob.readObject();
		if (in instanceof ElGamalPrivateKey)
		{
			e_sk = (ElGamalPrivateKey) in;
		}
		else if(in instanceof BigInteger)
		{
			e_sk = null;
			return;
		}
		else
		{
			throw new IllegalArgumentException("Invalid, did not receive ElGamal Private Key!");
		}
	}
	
	// Used to shuffle the encrypted bits
	// NOTE THIS METHOD DOES NOT ALLOCATE A NEW ARRAY!
	// SO BE CAREFUL WITH POINTER MANAGEMENT HERE!
	protected BigInteger [] shuffle_bits(BigInteger [] array)
	{
		for (int i = 0; i < array.length; i++) 
		{
			int randomPosition = rnd.nextInt(array.length);
		    BigInteger temp = array[i];
		    array[i] = array[randomPosition];
		    array[randomPosition] = temp;
		}
		return array;
	}

	// Below are all supported sorting techniques!
    
	// ----------------Bubble Sort-----------------------------------
	// ---------------We also use this to obtain K-Min/K-max items----
	
	private void bubbleSort(BigInteger [] arr)
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		boolean activation = false;
		for (int i = 0; i < arr.length - 1; i++)
		{
			for (int j = 0; j < arr.length - i - 1; j++)
			{
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = this.Protocol2(arr[j], arr[j + 1]);
				}
				else
				{
					activation = this.Protocol4(arr[j], arr[j + 1]);
				}
				
				// Originally arr[j] > arr[j + 1]
				if (activation)
				{
					// swap temp and arr[i]
					BigInteger temp = arr[j];
					arr[j] = arr[j + 1];
					arr[j + 1] = temp;
				}
			}
		}
	}
	
	public BigInteger[] getKMax(BigInteger [] input, int k) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		if(k > input.length || k <= 0)
		{
			throw new IllegalArgumentException("Invalid k value!");
		}
		BigInteger [] arr = deep_copy(input);
		BigInteger [] max = new BigInteger[k];
		
		boolean activation = false;
		for (int i = 0; i < k; i++)
		{
			for (int j = 0; j < arr.length - i - 1; j++)
			{
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = this.Protocol2(arr[j], arr[j + 1]);
				}
				else
				{
					activation = this.Protocol4(arr[j], arr[j + 1]);
				}
				
				// Originally arr[j] > arr[j + 1]
				// Protocol4 (x, y) --> [[x >= y]]
				if (activation)
				{
					// swap temp and arr[i]
					BigInteger temp = arr[j];
					arr[j] = arr[j + 1];
					arr[j + 1] = temp;
				}
			}
		}
		
		// Get last K-elements of arr!! 
		for (int i = 0; i < k; i++)
		{
			max[k - 1 - i] = arr[arr.length - 1 - i];
		}
		
		// Close Bob
		toBob.writeBoolean(false);
		toBob.flush();
		return max;
	}
	
	public List<ElGamal_Ciphertext> getKMin_ElGamal(List<ElGamal_Ciphertext> input, int k) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		if(k > input.size() || k <= 0)
		{
			throw new IllegalArgumentException("Invalid k value!");
		}
		// deep copy
		List<ElGamal_Ciphertext> arr = new ArrayList<ElGamal_Ciphertext>();
		for(ElGamal_Ciphertext p : input)
		{
		    arr.add(p);
		}
		
		ElGamal_Ciphertext temp;
		List<ElGamal_Ciphertext> min = new ArrayList<ElGamal_Ciphertext>();
		
		for (int i = 0; i < k; i++)
		{
			for (int j = 0; j < arr.size() - i - 1; j++)
			{
				toBob.writeBoolean(true);
				toBob.flush();
				
				// Originally arr[j] > arr[j + 1]
				if (!this.Protocol4(arr.get(j), arr.get(j + 1)))
				{
					// swap temp and arr[i]
					temp = arr.get(j);
					arr.set(j, arr.get(j + 1));
					arr.set(j + 1, temp);
				}
			}
		}
		
		// Get last K-elements of arr!! 
		for (int i = 0; i < k; i++)
		{
			min.add(arr.get(arr.size() - 1 - i));
		}
		
		if(e_sk != null)
		{
			System.out.println("ElGamal sorting");
			for(int i = 0; i < arr.size(); i++)
			{
				System.out.print(ElGamalCipher.decrypt(e_sk, arr.get(i)) + ", ");
			}
			System.out.println("");
			for(int i = 0; i < k; i++)
			{
				System.out.print(ElGamalCipher.decrypt(e_sk, min.get(i)) + ", ");
			}
			System.out.println("");
		}
		
		// Close Bob
		toBob.writeBoolean(false);
		toBob.flush();
		return min;
	}
	
	public BigInteger[] getKMin(BigInteger [] input, int k) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		if(k > input.length || k <= 0)
		{
			throw new IllegalArgumentException("Invalid k value!");
		}
		BigInteger [] arr = deep_copy(input);
		
		BigInteger [] min = new BigInteger[k];
		
		boolean activation = false;
		for (int i = 0; i < k; i++)
		{
			for (int j = 0; j < arr.length - 1 - i; j++)
			{
				toBob.writeBoolean(true);
				toBob.flush();
				// Might need a K-Max test as well!
				if(USE_PROTOCOL_2)
				{
					activation = this.Protocol2(arr[j], arr[j + 1]);
				}
				else
				{
					activation = this.Protocol4(arr[j], arr[j + 1]);
				}
				
				// Originally arr[j] > arr[j + 1]
				if (!activation)
				{
					// swap temp and arr[i]
					BigInteger temp = arr[j];
					arr[j] = arr[j + 1];
					arr[j + 1] = temp;
				}
			}
		}
		
		// Get last K-elements of arr!! 
		for (int i = 0; i < k; i++)
		{
			min[i] = arr[arr.length - 1 - i];
		}
		
		if(!isDGK && sk != null)
		{
			System.out.println("Paillier sorting...");
			for(int i = 0; i < arr.length; i++)
			{
				System.out.print(PaillierCipher.decrypt(arr[i], sk) + ", ");
			}
			System.out.println(" ");
			for(int i = 0; i < k; i++)
			{
				System.out.print(PaillierCipher.decrypt(min[i], sk) + ", ");
			}
			System.out.println("");
		}
		
		
		if(isDGK && privKey != null)
		{
			System.out.println("DGK sorting...");
			for(int i = 0; i < arr.length; i++)
			{
				System.out.print(DGKOperations.decrypt(arr[i], privKey) + ", ");
			}
			System.out.println(" ");
			for(int i = 0; i < k; i++)
			{
				System.out.print(DGKOperations.decrypt(min[i], privKey) + ", ");
			}
			System.out.println("");
		}
	
		// Close Bob
		toBob.writeBoolean(false);
		toBob.flush();
		return min;
	}
	
	public BigInteger[] getKMin(List<BigInteger> input, int k) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		if(k > input.size() || k <= 0)
		{
			throw new IllegalArgumentException("Invalid k value!");
		}
		// deep copy
		List<BigInteger> arr = new ArrayList<BigInteger>();
		for(BigInteger p : input)
		{
		    arr.add(p);
		}
		
		BigInteger [] min = new BigInteger[k];
		
		boolean activation = false;
		for (int i = 0; i < k; i++)
		{
			for (int j = 0; j < arr.size() - i - 1; j++)
			{
				toBob.writeBoolean(true);
				toBob.flush();
				if(USE_PROTOCOL_2)
				{
					activation = this.Protocol2(arr.get(j), arr.get(j + 1));
				}
				else
				{
					activation = this.Protocol4(arr.get(j), arr.get(j + 1));
				}
				
				// Originally arr[j] > arr[j + 1]
				if (!activation)
				{
					// swap temp and arr[i]
					BigInteger temp = arr.get(j);
					arr.set(j, arr.get(j + 1));
					arr.set(j + 1, temp);
				}
			}
		}
		
		// Get last K-elements of arr!! 
		for (int i = 0; i < k; i++)
		{
			min[i] = arr.get(arr.size() - 1 - i);
		}
		
		if(!isDGK && sk != null)
		{
			System.out.println(" ");
			for(int i = 0; i < k; i++)
			{
				System.out.print(PaillierCipher.decrypt(min[i], sk) + ", ");
			}
			System.out.println("");
		}
		
		if(isDGK && privKey != null)
		{
			System.out.println(" ");
			for(int i = 0; i < arr.size(); i++)
			{
				System.out.print(DGKOperations.decrypt(arr.get(i), privKey) + ", ");
			}
			System.out.println(" ");
			for(int i = 0; i < k; i++)
			{
				System.out.print(DGKOperations.decrypt(min[i], privKey) + ", ");
			}
			System.out.println("");
		}
		
		// Close Bob
		toBob.writeBoolean(false);
		toBob.flush();
		return min;
	}

	// --------------Quick Sort---------------------
	// Quick Sort
	/* This function takes last element as pivot,
	    places the pivot element at its correct
	    position in sorted array, and places all
	    smaller (smaller than pivot) to left of
	    pivot and all greater elements to right
	    of pivot */
	private int partition(BigInteger arr[], int low, int high)
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		boolean activation = false;
		BigInteger pivot = arr[high]; 
		int i = low - 1; // index of smaller element
		for (int j = low; j < high; j++)
		{
			// If current element is smaller than or equal to pivot
			toBob.writeBoolean(true);
			toBob.flush();
		
			// if (arr[j] <= pivot)
			if(USE_PROTOCOL_2)
			{
				activation = this.Protocol2(arr[j], pivot);
			}
			else
			{
				activation = this.Protocol4(arr[j], pivot);
			}
			
			if(!activation)
			{
				++i;
				// swap arr[i] and arr[j]
				BigInteger temp = arr[i];
				arr[i] = arr[j];
				arr[j] = temp;
			}
		}
		// swap arr[i+1] and arr[high] (or pivot)
		BigInteger temp = arr[i + 1];
		arr[i + 1] = arr[high];
		arr[high] = temp;
		return i + 1;
	}

	/* 
	 * The main function that implements QuickSort()
	 * arr[] --> Array to be sorted,
	 * low  --> Starting index,
	 * high  --> Ending index 
	 */
	private void sort(BigInteger arr[], int low, int high)
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		if (low < high)
		{
			/* pi is partitioning index, arr[pi] is 
	           now at right place */
			int pi = partition(arr, low, high);

			// Recursively sort elements before
			// partition and after partition
			sort(arr, low, pi - 1);
			sort(arr, pi + 1, high);
		}
	}
	
	// --------------Merge Sort---------------------
	private void doMergeSort(int lowerIndex, int higherIndex) 
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		if (lowerIndex < higherIndex)
		{
			int middle = lowerIndex + (higherIndex - lowerIndex) / 2;
			// Below step sorts the left side of the array
			doMergeSort(lowerIndex, middle);
			// Below step sorts the right side of the array
			doMergeSort(middle + 1, higherIndex);
			// Now merge both sides
			mergeParts(lowerIndex, middle, higherIndex);
		}
	}

	private void mergeParts(int lowerIndex, int middle, int higherIndex)
			throws ClassNotFoundException, IOException, IllegalArgumentException
	{
		boolean activation = false;
		int i = lowerIndex;
		int j = middle + 1;
		int k = lowerIndex;

		tempBigMerg = Arrays.copyOf(sortedArray, sortedArray.length);
		while (i <= middle && j <= higherIndex)
		{
			toBob.writeBoolean(true);
			// tempBigMerg[i] > tempBigMerg[j]
			if(USE_PROTOCOL_2)
			{
				activation = this.Protocol2(tempBigMerg[i], tempBigMerg[j]);
			}
			else
			{
				activation = this.Protocol4(tempBigMerg[i], tempBigMerg[j]);
			}
			
			if (activation)
			{
				sortedArray[k] = tempBigMerg[i];
				++i;
			}
			else
			{
				sortedArray[k] = tempBigMerg[j];
				++j;
			}
			++k;
		}
		while (i <= middle)
		{
			sortedArray[k] = tempBigMerg[i];
			++k;
			++i;
		}
	}
	
	// BigIntegers are immutable, this should do the trick
	protected BigInteger [] deep_copy(BigInteger [] input)
	{
		BigInteger [] copy = new BigInteger[input.length];
		for(int i = 0; i < input.length;i++)
		{
			copy[i] = input[i];
		}
		return copy;
	}
	
	public void writeObject(Object o) throws IOException
	{
		toBob.writeObject(o);
		toBob.flush();
	}
	
	public Object readObject() throws ClassNotFoundException, IOException
	{
		return fromBob.readObject();
	}
	
	public void run() 
	{
		try
		{
			sortArray();
		}
		catch (ClassNotFoundException | IOException | IllegalArgumentException e) 
		{
			e.printStackTrace();
		}
	}
}
