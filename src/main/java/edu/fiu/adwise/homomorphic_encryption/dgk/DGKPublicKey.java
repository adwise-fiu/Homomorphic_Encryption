/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.dgk;

import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.HashMap;

import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;

/**
 * Represents the public key for the DGK (Damgård-Geisler-Krøigaard) cryptosystem.
 * This class implements the Serializable, DGK_Key, PublicKey, Runnable, and CipherConstants interfaces.
 * It provides methods for key generation, serialization, and lookup table generation for encryption operations.
 */
public final class DGKPublicKey implements Serializable, DGK_Key, PublicKey, Runnable, CipherConstants {
	@Serial
	private static final long serialVersionUID = -1613333167285302035L;
	/** The modulus \( n \) used in the DGK cryptosystem. */
	final BigInteger n;

	/** The generator \( g \) used in the DGK cryptosystem. */
	final BigInteger g;

	/** The secondary generator \( h \) used in the DGK cryptosystem. */
	final BigInteger h;

	/** The order of the subgroup as a long value. */
	final long u;

	/** The order of the subgroup as a BigInteger. */
	final BigInteger bigU;

	/** The lookup table for \( g^i \mod n \) values. */
	final HashMap<Long, BigInteger> gLUT = new HashMap<>();

	/** The lookup table for \( h^i \mod n \) values. */
	private final HashMap<Long, BigInteger> hLUT = new HashMap<>();

	// Key Parameters
	/** The bit length of plaintext values. */
	final int l;

	/** The security parameter used in the DGK cryptosystem. */
	final int t;

	/** The key length used in the DGK cryptosystem. */
	final int k;

	/** The encrypted representation of the value 1. */
	private BigInteger ONE = null;

	/** The encrypted representation of the value 0. */
	private BigInteger ZERO = null;

	/**
	 * Constructs a DGKPublicKey with all required parameters.
	 *
	 * @param n The modulus.
	 * @param g The generator.
	 * @param h The secondary generator.
	 * @param u The order of the subgroup.
	 * @param l The bit length of plaintext.
	 * @param t The security parameter.
	 * @param k The key size.
	 */
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
	}

	/**
	 * Serializes the public key to a file.
	 *
	 * @param dgk_public_key_file The file path to save the public key.
	 * @throws IOException If an I/O error occurs.
	 */
	public void writeKey(String dgk_public_key_file)  throws IOException {
		// clear hashmaps
		hLUT.clear();
		gLUT.clear();
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(dgk_public_key_file))) {
			oos.writeObject(this);
			oos.flush();
		}
	}

	/**
	 * Deserializes a DGKPublicKey from a file.
	 *
	 * @param dgk_public_key The file path to read the public key from.
	 * @return The deserialized DGKPublicKey.
	 * @throws IOException If an I/O error occurs.
	 * @throws ClassNotFoundException If the class cannot be found.
	 */
	public static DGKPublicKey readKey(String dgk_public_key) throws IOException, ClassNotFoundException {
		DGKPublicKey pk;
		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(dgk_public_key))) {
			pk = (DGKPublicKey) ois.readObject();
		}
		pk.generategLUT();
		pk.generatehLUT();
		return pk;
	}

	/**
	 * @return The encrypted representation of 0.
	 * @throws HomomorphicException - If an invalid input was found, this should be impossible in this case
	 */
	public BigInteger ZERO() throws HomomorphicException {
		if (ZERO == null) {
			ZERO = DGKOperations.encrypt(0, this);
		}
		return ZERO;
	}

	/**
	 * @return The encrypted representation of 1.
	 * @throws HomomorphicException - If an invalid input was found, this should be impossible in this case
	 */
	public BigInteger ONE() throws HomomorphicException {
		if (ONE == null) {
			ONE = DGKOperations.encrypt(1, this);
		}
		return ONE;
	}

	/**
	 * @return The algorithm name ("DGK").
	 */
	public String getAlgorithm() {
		return "DGK";
	}

	/**
	 * @return A string representation of the DGK public key.
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

	/**
	 * @return The format of the key ("X.509").
	 */
	public String getFormat() {
		return "X.509";
	}

	/**
	 * @return The encoded form of the key (currently null).
	 */
	public byte[] getEncoded() {
		return null;
	}

	/**
	 * Generates the lookup tables for g and h.
	 */
	public void run() {
		this.generatehLUT();
		this.generategLUT();
	}

	/**
	 * Generates the lookup table for h^i mod n values.
	 */
	private void generatehLUT() {		
		for (long i = 0; i < 2L * t; ++i) {
			// e = 2^i (mod n)
			// h^{2^i (mod n)} (mod n)
			// f(i) = h^{2^i}(mod n)
			BigInteger e = TWO.pow((int) i).mod(this.n);
			this.hLUT.put(i, this.h.modPow(e, this.n));
		}
	}

	/**
	 * Generates the lookup table for g^i mod n values.
	 */
	private void generategLUT() {	
		for (long i = 0; i < this.u; ++i) {
			BigInteger out = this.g.modPow(BigInteger.valueOf(i), this.n);
			this.gLUT.put(i, out);
		}
	}

	/**
	 * @return The order of the subgroup as a long.
	 */
	public long getu() {
		return this.u;
	}

	/**
	 * @return The order of the subgroup as a BigInteger.
	 */
	public BigInteger getU() {
		return this.bigU;
	}

	/**
	 * @return The modulus n.
	 */
	public BigInteger getN() {
		return this.n;
	}

	/**
	 * @return The bit length of plaintext.
	 */
	public int getL() {
		return this.l;
	}

	/**
	 * @return The security parameter.
	 */
	public int getT() {
		return this.t;
	}

	/**
	 * Compares this DGKPublicKey with another object for equality.
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
		DGKPublicKey that = (DGKPublicKey) o;
		return this.toString().equals(that.toString());
	}
}