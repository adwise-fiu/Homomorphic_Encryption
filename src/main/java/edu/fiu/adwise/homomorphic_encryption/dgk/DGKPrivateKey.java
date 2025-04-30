/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.dgk;

import java.io.*;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import edu.fiu.adwise.homomorphic_encryption.misc.NTL;

/**
 * Represents a DGK (Damgård-Geisler-Krøigaard) private key used for homomorphic encryption.
 * This class implements the {@link Serializable}, {@link DGK_Key}, and {@link PrivateKey} interfaces.
 * It contains both private and public key parameters, as well as methods for key serialization,
 * deserialization, and lookup table generation.
 */
public final class DGKPrivateKey implements Serializable, DGK_Key, PrivateKey {
	@Serial
	private static final long serialVersionUID = 4574519230502483629L;
	// Private Key Parameters
	final BigInteger p; // First prime factor of n
	private final BigInteger q; // Second prime factor of n
	final BigInteger vp; // Precomputed value for decryption
	private final BigInteger vq; // Precomputed value for decryption
	final Map<BigInteger, Long> LUT; // Lookup table for decryption

	// Public key parameters
	final BigInteger n; // Modulus
	final BigInteger g; // Generator
	private final BigInteger h; // Auxiliary generator
	private final long u; // Upper bound for plaintext values
	private final BigInteger bigU; // BigInteger representation of u

	// Key Parameters
	private final int l; // Bit length of plaintext
	private final int t; // Security parameter
	private final int k; // Key length

	// Signature
	public final BigInteger v; // Product of vp and vq

	/**
	 * Constructs a DGKPrivateKey using the provided private key parameters and public key.
	 *
	 * @param p       First prime factor of n
	 * @param q       Second prime factor of n
	 * @param vp      Precomputed value for decryption
	 * @param vq      Precomputed value for decryption
	 * @param pubKey  Corresponding DGK public key
	 */
	public DGKPrivateKey (BigInteger p, BigInteger q, BigInteger vp,
			BigInteger vq, DGKPublicKey pubKey) {
		this.p = p;
		this.q = q;
		this.vp = vp;
		this.vq = vq;
		this.v = vp.multiply(vq);

		// Public Key Parameters
		this.n = pubKey.n;
		this.g = pubKey.g;
		this.h = pubKey.h;
		this.u = pubKey.u;
		this.bigU = pubKey.bigU;

		// Key Parameters
		this.l = pubKey.l;
		this.t = pubKey.t;
		this.k = pubKey.k;

		// I already know the size of my map, so just initialize the size now to avoid memory waste!
		this.LUT = new HashMap<>((int) this.u, (float) 1.0);

		// Now that I have public key parameters, build LUT!
		this.generategLUT();
	}

	/**
	 * Serializes the private key to a file.
	 *
	 * @param dgk_private_key_file Path to the file where the private key will be saved
	 * @throws IOException If an I/O error occurs during serialization
	 */
	public void writeKey(String dgk_private_key_file) throws IOException {
		LUT.clear();
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(dgk_private_key_file))) {
			oos.writeObject(this);
			oos.flush();
		}
	}

	/**
	 * Deserializes a DGK private key from a file.
	 *
	 * @param dgk_private_key Path to the file containing the serialized private key
	 * @return The deserialized DGKPrivateKey object
	 * @throws IOException            If an I/O error occurs during deserialization
	 * @throws ClassNotFoundException If the class of the serialized object cannot be found
	 */
	public static DGKPrivateKey readKey(String dgk_private_key) throws IOException, ClassNotFoundException {
		DGKPrivateKey sk;
		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(dgk_private_key))) {
			sk = (DGKPrivateKey) ois.readObject();
		}
		sk.generategLUT();
		return sk;
	}

	/**
	 * Generates the lookup table (LUT) for decryption.
	 * The LUT maps ciphertext values to their corresponding plaintext values.
	 */
	private void generategLUT() {
		BigInteger gvp = NTL.POSMOD(this.g.modPow(this.vp, this.p), this.p);
		for (long i = 0; i < this.u; ++i)
		{
			BigInteger decipher = gvp.modPow(BigInteger.valueOf(i), this.p);
			this.LUT.put(decipher, i);
		}
	}

	/**
	 * Returns a string representation of the public key parameters.
	 * Private key parameters are excluded for security reasons.
	 *
	 * @return A string representation of the public key parameters
	 */
	public String toString() {
		String answer = "";
		answer += "n: " + this.n + '\n';
		answer += "g: " + this.g + '\n';
		answer += "h: " + this.h + '\n';
		answer += "u: " + this.bigU + '\n';
		answer += "l: " + this.l + '\n';
		answer += "t: " + this.t + '\n';
		answer += "k: " + this.k + '\n';
		// COMMENTED OUT TO HIDE SECRET KEY PARAMETERS
		return answer;
	}

	/**
	 * Returns the upper bound for plaintext values.
	 *
	 * @return The upper bound for plaintext values
	 */
	public BigInteger getU() {
		return this.bigU;
	}

	/**
	 * Returns the modulus of the key.
	 *
	 * @return The modulus of the key
	 */
	public BigInteger getN() {
		return this.n;
	}

	/**
	 * Returns the bit length of plaintext values.
	 *
	 * @return The bit length of plaintext values
	 */
	public int getL() {
		return this.l;
	}

	/**
	 * Returns the algorithm name.
	 *
	 * @return The algorithm name ("DGK")
	 */
	public String getAlgorithm() {
		return "DGK";
	}

	/**
	 * Returns the format of the key.
	 *
	 * @return The format of the key ("PKCS#8")
	 */
	public String getFormat() {
		return "PKCS#8";
	}

	/**
	 * Returns the encoded form of the key.
	 * This implementation returns null as encoding is not supported.
	 *
	 * @return null
	 */
	public byte[] getEncoded() {
		return null;
	}

	/**
	 * Compares this DGKPrivateKey with another object for equality.
	 *
	 * @param o The object to compare with
	 * @return true if the objects are equal, false otherwise
	 */
	public boolean equals (Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		DGKPrivateKey that = (DGKPrivateKey) o;
		return this.toString().equals(that.toString());
	}
}