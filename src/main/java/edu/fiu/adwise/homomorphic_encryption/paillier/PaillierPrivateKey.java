package edu.fiu.adwise.homomorphic_encryption.paillier;

import java.io.*;
import java.math.BigInteger;
import java.security.PrivateKey;


/**
 * This class represents a private key in the Paillier cryptosystem.
 * It implements the {@link PaillierKey} and {@link PrivateKey} interfaces
 * and is also serializable.
 */
public final class PaillierPrivateKey implements Serializable, PaillierKey, PrivateKey {
	//private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();
	@Serial
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

	/**
	 * Constructs a Paillier private key with the specified parameters.
	 *
	 * @param key_size The size of the key in bits.
	 * @param n        The value of n (product of two primes p and q).
	 * @param mod      The modulus (n^2).
	 * @param lambda   The Carmichael's function value.
	 * @param mu       The modular inverse of lambda mod n.
	 * @param g        The generator g.
	 * @param alpha    The smallest divisor of lcm(p-1, q-1).
	 */
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

	/**
	 * Writes the private key to a file.
	 *
	 * @param paillier_private_key_file The file path to save the private key.
	 * @throws IOException If an I/O error occurs.
	 */
	public void writeKey(String paillier_private_key_file) throws IOException {
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(paillier_private_key_file))) {
			oos.writeObject(this);
			oos.flush();
		}
	}

	/**
	 * Reads a private key from a file.
	 *
	 * @param paillier_private_key The file path to read the private key from.
	 * @return The {@link PaillierPrivateKey} object.
	 * @throws IOException            If an I/O error occurs.
	 * @throws ClassNotFoundException If the class of the serialized object cannot be found.
	 */
	public static PaillierPrivateKey readKey(String paillier_private_key) throws IOException, ClassNotFoundException {
		PaillierPrivateKey sk;
		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(paillier_private_key))) {
			sk = (PaillierPrivateKey) ois.readObject();
		}
		return sk;
	}

	/**
	 * Returns a string representation of the private key, omitting secret parameters.
	 *
	 * @return A string representation of the private key.
	 */
	public String toString() {
		String answer = "";
		answer += "key_size = " + this.key_size + ", " + '\n';
		answer += "n =        " + this.n + ", " + '\n';
		answer += "modulus =  " + this.modulus + '\n';
		answer += "g =        " + this.g + '\n';
		return answer;
	}

	/**
	 * Retrieves the value of n, which is part of the Paillier key.
	 *
	 * @return The value of n as a {@link BigInteger}.
	 */
	public BigInteger getN() {
		return n;
	}

	/**
	 * Retrieves the modulus used in the Paillier cryptosystem.
	 *
	 * @return The modulus as a {@link BigInteger}.
	 */
	public BigInteger getModulus() {
		return this.modulus;
	}

	/**
	 * Returns the algorithm name for this key.
	 *
	 * @return The algorithm name ("Paillier").
	 */
	public String getAlgorithm() {
		return "Paillier";
	}

	/**
	 * Returns the format of the key encoding.
	 *
	 * @return The format ("PKCS#8").
	 */
	public String getFormat() {
		return "PKCS#8";
	}

	/**
	 * Returns the encoded form of the key.
	 *
	 * @return The encoded key as a byte array, or null if not supported.
	 */
	public byte[] getEncoded() {
		return null;
	}

	/**
	 * Compares this private key with another object for equality.
	 *
	 * @param o The object to compare with.
	 * @return True if the objects are equal, false otherwise.
	 */
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