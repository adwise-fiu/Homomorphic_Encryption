package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

public abstract class socialist_millionaires 
{
	protected final static BigInteger TWO = new BigInteger("2");
	protected final SecureRandom rnd = new SecureRandom();
	protected final static int SIGMA = 80;
	protected final static int BILLION = BigInteger.TEN.pow(9).intValue();

	protected boolean FAST_DIVIDE = false;
	protected boolean isDGK = false;

	// Both Alice and Bob will have keys
	protected PaillierPublicKey paillier_public = null;
	protected DGKPublicKey dgk_public = null;
	protected ElGamalPublicKey el_gamal_public = null;
	
	// Key Master
	protected PaillierPrivateKey paillier_private = null;
	protected DGKPrivateKey dgk_private = null;
	protected ElGamalPrivateKey el_gamal_private = null;

	// Both use 2^l
	protected BigInteger powL;
	
	//I/O
	protected ObjectOutputStream toBob = null;
	protected ValidatingObjectInputStream fromBob = null;
	protected ObjectOutputStream toAlice = null;
	protected ValidatingObjectInputStream fromAlice = null;

	public void setDGKMode(boolean isDGK) {
		this.isDGK = isDGK;
	}

	public boolean isDGK() {
		return isDGK;
	}

	// Set Public Key
	public void setPaillierPublicKey(PaillierPublicKey paillier_public) {
		this.paillier_public = paillier_public;
	}

	public void setDGKPublicKey(DGKPublicKey dgk_public) {
		this.dgk_public = dgk_public;
		this.powL = TWO.pow(this.dgk_public.getL());
	}

	public void setElGamalPublicKey(ElGamalPublicKey el_gamal_public) {
		this.el_gamal_public = el_gamal_public;
	}

	// Get PublicKey
	public PaillierPublicKey getPaillierPublicKey() {
		return paillier_public;
	}

	public DGKPublicKey getDGKPublicKey() {
		return dgk_public;
	}

	public ElGamalPublicKey getElGamalPublicKey() {
		return el_gamal_public;
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
	 */
	protected BigInteger [] deep_copy(BigInteger [] input) {
		BigInteger [] copy = new BigInteger[input.length];
		System.arraycopy(input, 0, copy, 0, input.length);
		return copy;
	}
	
	/**
	 *  Used to shuffle the encrypted bits.
	 *  Note: IT DOES NOT CREATE A NEW ARRAY.
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
