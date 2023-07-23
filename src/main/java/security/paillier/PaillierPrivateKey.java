package security.paillier;

import java.io.*;
import java.math.BigInteger;
import java.security.PrivateKey;

public final class PaillierPrivateKey implements Serializable, PaillierKey, PrivateKey
{
	//private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();
	private static final long serialVersionUID = -3342551807566493368L;

	// k1 is the security parameter. It is the number of bits in n.
	private final int key_size;

	final BigInteger n;
	final BigInteger modulus;
	final BigInteger g;

	final BigInteger lambda;
	private final BigInteger mu;

	final BigInteger rho;
	private final BigInteger alpha;

	public PaillierPrivateKey(int key_size, BigInteger n, BigInteger mod, 
			BigInteger lambda, BigInteger mu, BigInteger g, BigInteger alpha)
	{
		this.key_size = key_size;
		this.n = n;
		this.modulus = mod;
		this.lambda = lambda;
		this.mu = mu;
		this.g = g;
		this.alpha = alpha;
		this.rho = PaillierCipher.L(this.g.modPow(this.lambda, this.modulus), this.n).modInverse(this.modulus);
	}

	public void writeKey(String paillier_private_key_file) throws IOException {
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(paillier_private_key_file))) {
			oos.writeObject(this);
			oos.flush();
		}
	}

	public static PaillierPrivateKey readKey(String paillier_private_key) throws IOException, ClassNotFoundException {
		PaillierPrivateKey sk;
		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(paillier_private_key))) {
			sk = (PaillierPrivateKey) ois.readObject();
		}
		return sk;
	}

	// Omitting secret key parameters
	public String toString() {
		String answer = "";
		answer += "key_size = " + this.key_size + ", " + '\n';
		answer += "n =        " + this.n + ", " + '\n';
		answer += "modulus =  " + this.modulus + '\n';
		answer += "g =        " + this.g + '\n';
		return answer;
	}

	public BigInteger getN() {
		return n;
	}

	public BigInteger getModulus() {
		return this.modulus;
	}

	public String getAlgorithm() {
		return "Paillier";
	}

	public String getFormat() {
		return "PKCS#8";
	}
	
	public byte[] getEncoded() {
		return null;
	}

	public boolean equals (Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		PaillierPrivateKey that = (PaillierPrivateKey) o;
		return this.toString().equals(that.toString());
	}
}