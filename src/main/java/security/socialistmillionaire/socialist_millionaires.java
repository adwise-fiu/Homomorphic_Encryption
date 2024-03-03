package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.misc.CipherConstants;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

public abstract class socialist_millionaires implements CipherConstants
{
	protected static final SecureRandom rnd = new SecureRandom();
	protected final static int SIGMA = 80;

	protected boolean FAST_DIVIDE = false;
	protected boolean isDGK = false;

	// Both Alice and Bob will have keys
	protected PaillierPublicKey paillier_public = null;
	protected DGKPublicKey dgk_public = null;
	protected ElGamalPublicKey el_gamal_public = null;
	
	// Hold keys
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

	// Confirm if using TLS sockets (encryption in transit for last few steps)
	protected boolean tls_socket_in_use = false;

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

	public boolean readBoolean() throws IOException {
		if(fromBob != null) {
			return fromBob.readBoolean();
		}
		else {
			return fromAlice.readBoolean();
		}
	}

	public void writeBoolean(boolean value) throws IOException {
		if(toBob != null) {
			toBob.writeBoolean(value);
			toBob.flush();
		}
		else {
			toAlice.writeBoolean(value);
			toAlice.flush();
		}
	}

	public int readInt() throws IOException {
		if (fromBob != null) {
			return fromBob.readInt();
		}
		else {
			return fromAlice.readInt();
		}
	}

	public void writeInt(int value) throws IOException {
		if (toBob != null) {
			toBob.writeInt(value);
			toBob.flush();
		}
		else {
			toAlice.writeInt(value);
			toAlice.flush();
		}
	}

	public Object readObject() throws IOException, ClassNotFoundException {
		if(fromBob != null) {
			return fromBob.readObject();
		}
		else {
			return fromAlice.readObject();
		}
	}
	
	public void writeObject(Object o) throws IOException {
		if(toBob != null) {
			toBob.writeObject(o);
			toBob.flush();
		}
		else {
			toAlice.writeObject(o);
			toAlice.flush();	
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
