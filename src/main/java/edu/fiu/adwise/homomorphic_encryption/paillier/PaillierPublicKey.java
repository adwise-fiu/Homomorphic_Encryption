package edu.fiu.adwise.homomorphic_encryption.paillier;

import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;

import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;

public final class PaillierPublicKey implements Serializable, PaillierKey, PublicKey {
	@Serial
	private static final long serialVersionUID = -4009702553030484256L;

	/**
	 * The size of the key in bits.
	 */
	public final int key_size;

	/**
	 * The value of n, which is the product of two large primes (p and q).
	 */
	final BigInteger n;

	/**
	 * The modulus, which is n^2.
	 */
	final BigInteger modulus;
	/**
	 * The generator g used in the Paillier cryptosystem.
	 */
	final BigInteger g;
	/**
	 * Cached value representing the encryption of zero.
	 */
	BigInteger ZERO = null;

	/**
	 * Constructs a Paillier public key with the specified parameters.
	 *
	 * @param key_size The size of the key in bits.
	 * @param n        The value of n (product of two primes p and q).
	 * @param modulus  The modulus (n^2).
	 * @param g        The generator g.
	 */
	public PaillierPublicKey(int key_size, BigInteger n, BigInteger modulus, BigInteger g) {
		this.key_size = key_size;
		this.n = n;
		this.modulus = modulus;
		this.g = g;

	}

	/**
	 * Retrieves the encryption of zero using this public key.
	 *
	 * @return The encryption of zero as a {@link BigInteger}.
	 * @throws HomomorphicException If an error occurs during encryption.
	 */
	public BigInteger ZERO() throws HomomorphicException {
		if (ZERO == null) {
			this.ZERO = PaillierCipher.encrypt(0, this);
		}
		return this.ZERO;
	}

	/**
	 * Returns a string representation of the public key.
	 *
	 * @return A string representation of the public key.
	 */
	public String toString() {
		String answer = "";
		answer += "k1 = " + this.key_size + ", " + '\n';
		answer += "n = " + this.n + ", " + '\n';
		answer += "modulus = " + this.modulus + '\n';
		answer += "g = " + this.g + '\n';
		return answer;
	}

	/**
	 * Writes the public key to a file.
	 *
	 * @param paillier_public_key_file The file path to save the public key.
	 * @throws IOException If an I/O error occurs.
	 */
	public void writeKey(String paillier_public_key_file) throws IOException {
		// Write the key to a file
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(paillier_public_key_file))) {
			oos.writeObject(this);
			oos.flush();
		}
	}

	/**
	 * Reads a public key from a file.
	 *
	 * @param paillier_public_key The file path to read the public key from.
	 * @return The {@link PaillierPublicKey} object.
	 * @throws IOException            If an I/O error occurs.
	 * @throws ClassNotFoundException If the class of the serialized object cannot be found.
	 */
	public static PaillierPublicKey readKey(String paillier_public_key) throws IOException, ClassNotFoundException {
		PaillierPublicKey pk;
		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(paillier_public_key))) {
			pk = (PaillierPublicKey) ois.readObject();
		}
		return pk;
	}

	/**
	 * Retrieves the value of n, which is part of the Paillier key.
	 *
	 * @return The value of n as a {@link BigInteger}.
	 */
	public BigInteger getN() {
		return this.n;
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
	 * @return The format ("X.509").
	 */
	public String getFormat() {
		return "X.509";
	}

	/**
	 * Returns the encoded form of the key.
	 *
	 * @return The encoded key as a byte array, or null if not supported.
	 */
	public byte[] getEncoded() 
	{
		return null;
	}

	/**
	 * Compares this public key with another object for equality.
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
		PaillierPublicKey that = (PaillierPublicKey) o;
		return this.toString().equals(that.toString());
	}
}