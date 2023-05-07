package security.paillier;

import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;

public final class PaillierPublicKey implements Serializable, PaillierKey, PublicKey
{
	private static final long serialVersionUID = -4009702553030484256L;

	public final int key_size;

	// n = pq is a product of two large primes (such N is known as RSA modulus)
	final BigInteger n;
	final BigInteger modulus;
	final BigInteger g;

	public PaillierPublicKey(int key_size, BigInteger n, BigInteger modulus, BigInteger g) {
		this.key_size = key_size;
		this.n = n;
		this.modulus = modulus;
		this.g = g;
	}

	public String toString() {
		String answer = "";
		answer += "k1 = " + this.key_size + ", " + '\n';
		answer += "n = " + this.n + ", " + '\n';
		answer += "modulus = " + this.modulus + '\n';
		answer += "g = " + this.g + '\n';
		return answer;
	}

	public void writeKey(String paillier_public_key_file) {
		// Write the key to a file
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(paillier_public_key_file))) {
			oos.writeObject(this);
			oos.flush();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static PaillierPublicKey readKey(String paillier_public_key) {
		PaillierPublicKey pk;
		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(paillier_public_key))) {
			pk = (PaillierPublicKey) ois.readObject();
		} catch (IOException | ClassNotFoundException e) {
			throw new RuntimeException(e);
		}
		return pk;
	}

	public BigInteger getN() {
		return this.n;
	}

	public BigInteger getModulus() {
		return this.modulus;
	}

	public String getAlgorithm() {
		return "Paillier";
	}

	public String getFormat() {
		return "X.509";
	}

	public byte[] getEncoded() 
	{
		return null;
	}

	public boolean equals (Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		PaillierPublicKey that = (PaillierPublicKey) o;
		return this.toString().equals(that.toString());
	}
}