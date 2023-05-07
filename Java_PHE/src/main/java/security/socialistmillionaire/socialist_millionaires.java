package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

public abstract class socialist_millionaires 
{
	protected final static BigInteger TWO = new BigInteger("2");
	protected final SecureRandom rnd = new SecureRandom();
	protected final static int SIGMA = 80;
	protected final static int BILLION = BigInteger.TEN.pow(9).intValue();
	
	// Ensure Alice and Bob have the same settings!
	// May enable users to set this at Runtime?
	protected boolean USE_PROTOCOL_2 = false;
	protected boolean FAST_DIVIDE = false;
	protected boolean isDGK = false;

	// Both Alice and Bob will have keys
	protected PaillierPublicKey pk = null;
	protected DGKPublicKey pubKey = null;
	protected ElGamalPublicKey e_pk = null;
	
	// Key Master
	protected PaillierPrivateKey sk = null;
	protected DGKPrivateKey privKey = null;
	protected ElGamalPrivateKey e_sk = null;

	// Both use 2^l
	protected BigInteger powL;
	
	//I/O
	protected ObjectOutputStream toBob = null;
	protected ObjectInputStream fromBob = null;
	protected ObjectOutputStream toAlice = null;
	protected ObjectInputStream fromAlice = null;

	public void setDGKMode(boolean isDGK) {
		this.isDGK = isDGK;
	}

	public boolean isDGK() {
		return isDGK;
	}

	// Set Public Key
	public void setPaillierPublicKey(PaillierPublicKey pk) {
		this.pk = pk;
	}

	public void setDGKPublicKey(DGKPublicKey pubKey) {
		this.pubKey = pubKey;
	}

	public void setElGamalPublicKey(ElGamalPublicKey e_pk) {
		this.e_pk = e_pk;
	}

	// Get PublicKey
	public PaillierPublicKey getPaillierPublicKey() {
		return pk;
	}

	public DGKPublicKey getDGKPublicKey() {
		return pubKey;
	}

	public ElGamalPublicKey getElGamalPublicKey() {
		return e_pk;
	}
	
	public void writeObject(Object o) throws IOException
	{
		if(toBob != null) {
			toBob.writeObject(o);
			toBob.flush();
		}
		else {
			toAlice.writeObject(o);
			toAlice.flush();	
		}
	}
	
	public Object readObject() throws ClassNotFoundException, IOException
	{
		if (fromBob != null) {
			return fromBob.readObject();	
		}
		else {
			return fromAlice.readObject();
		}
	}
	
	/**
	 * Create deep copy of BigInteger array
	 * @param input
	 */
	protected BigInteger [] deep_copy(BigInteger [] input) {
		BigInteger [] copy = new BigInteger[input.length];
		System.arraycopy(input, 0, copy, 0, input.length);
		return copy;
	}
	
	/**
	 *  Used to shuffle the encrypted bits.
	 *  Note: IT DOES NOT CREATE A NEW ARRAY.
	 * @param array
	 * @return - shuffled array
	 */
	protected BigInteger[] shuffle_bits(BigInteger[] array) {
		for (int i = 0; i < array.length; i++) {
			int randomPosition = rnd.nextInt(array.length);
			BigInteger temp = array[i];
			array[i] = array[randomPosition];
			array[randomPosition] = temp;
		}
		return array;
	}
}
