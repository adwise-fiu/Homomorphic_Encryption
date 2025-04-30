package edu.fiu.adwise.homomorphic_encryption.elgamal;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;

/**
 * Represents an ElGamal ciphertext consisting of two components: g^r and m * h^r (or g^m * h^r).
 * This class is used in the ElGamal encryption scheme.
 */
public class ElGamal_Ciphertext implements Serializable {
	@Serial
	private static final long serialVersionUID = -4168027417302369803L;

	/** The first component of the ciphertext, g^r. */
	public final BigInteger gr;

	/** The second component of the ciphertext, m * h^r or g^m * h^r. */
	public final BigInteger hrgm;

	/**
	 * Constructs an ElGamal ciphertext with the given components.
	 *
	 * @param gr The first component of the ciphertext (g^r).
	 * @param mhr The second component of the ciphertext (m * h^r or g^m * h^r).
	 */
	public ElGamal_Ciphertext(BigInteger gr, BigInteger mhr) {
		this.gr = gr;
		this.hrgm = mhr;
	}

	/**
	 * Retrieves the first component of the ciphertext (g^r).
	 *
	 * @return The first component of the ciphertext.
	 */
	public BigInteger getA() {
		return this.gr;
	}

	/**
	 * Retrieves the second component of the ciphertext (m * h^r or g^m * h^r).
	 *
	 * @return The second component of the ciphertext.
	 */
	public BigInteger getB() {
		return this.hrgm;
	}
}