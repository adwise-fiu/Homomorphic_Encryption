package security.dgk;

import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.HashMap;

import security.misc.CipherConstants;

public final class DGKPublicKey implements Serializable, DGK_Key, PublicKey, Runnable, CipherConstants
{
	/**
	 * The type fingerprint that is set to indicate serialization compatibility with a previous version of the type.
	 */
	private static final long serialVersionUID = -1613333167285302035L;
	
	final BigInteger n;
	final BigInteger g;
	final BigInteger h;
	final long u;
	final BigInteger bigU;
	final HashMap <Long, BigInteger> gLUT = new HashMap<>();
	private final HashMap <Long, BigInteger> hLUT = new HashMap<>();
	
	// Key Parameters
	final int l;
	final int t;
	final int k;
	public final BigInteger ONE;

	//DGK Constructor with ALL parameters
	public DGKPublicKey(BigInteger n, BigInteger g, BigInteger h, BigInteger u,
						int l, int t, int k) {
		this.n = n;
		this.g = g;
		this.h = h;
		this.u = u.longValue();
		this.bigU = u;
		this.l = l; 
		this.t = t;
		this.k = k;
		ONE = DGKOperations.encrypt(BigInteger.ONE, this);
	}

	public void writeKey(String dgk_public_key_file)  throws IOException {
		// clear hashmaps
		hLUT.clear();
		gLUT.clear();
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(dgk_public_key_file))) {
			oos.writeObject(this);
			oos.flush();
		}
	}

	public static DGKPublicKey readKey(String dgk_public_key) throws IOException, ClassNotFoundException {
		DGKPublicKey pk;
		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(dgk_public_key))) {
			pk = (DGKPublicKey) ois.readObject();
		}
		pk.generategLUT();
		pk.generatehLUT();
		return pk;
	}

	public BigInteger ZERO() {
		return DGKOperations.encrypt(0, this);
	}

	/**
	 * @return DGK
	 */
	public String getAlgorithm() {
		return "DGK";
	}

	/**
	 * @return String representation of DGK Public Key
	 */
	public String toString() {
		String answer = "";
		answer += "n: " + n + ", " + '\n';
		answer += "g: " + g + ", " + '\n';
		answer += "h: " + h + ", " + '\n';
		answer += "u: " + bigU + ", " + '\n';
		answer += "l: " + l + ", " + '\n';
		answer += "t: " + t + ", " + '\n';
		answer += "k: " + k + ", " + '\n';
		return answer;
	}

	public String getFormat() {
		return "X.509";
	}

	public byte[] getEncoded() {
		return null;
	}

	public void run() {
		this.generatehLUT();
		this.generategLUT();
	}

	private void generatehLUT() {		
		for (long i = 0; i < 2L * t; ++i) {
			// e = 2^i (mod n)
			// h^{2^i (mod n)} (mod n)
			// f(i) = h^{2^i}(mod n)
			BigInteger e = TWO.pow((int) i).mod(this.n);
			this.hLUT.put(i, this.h.modPow(e, this.n));
		}
	}

	private void generategLUT() {	
		for (long i = 0; i < this.u; ++i) {
			BigInteger out = this.g.modPow(BigInteger.valueOf(i), this.n);
			this.gLUT.put(i, out);
		}
	}
	
	public long getu() {
		return this.u;
	}

	public BigInteger getU() {
		return this.bigU;
	}

	public BigInteger getN() {
		return this.n;
	}

	public int getL() {
		return this.l;
	}

	public boolean equals (Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		DGKPublicKey that = (DGKPublicKey) o;
		return this.toString().equals(that.toString());
	}
}