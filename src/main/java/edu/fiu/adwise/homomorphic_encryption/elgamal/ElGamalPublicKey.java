package edu.fiu.adwise.homomorphic_encryption.elgamal;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

/**
 * Represents the public key for the ElGamal encryption scheme.
 */
public final class ElGamalPublicKey implements Serializable, PublicKey, ElGamal_Key
{
	@Serial
	private static final long serialVersionUID = -6796919675914392847L;
	final BigInteger p;
	final BigInteger g;
	final BigInteger h;
	public boolean additive;

	/**
	 * Constructs an ElGamalPublicKey with the specified parameters.
	 *
	 * @param p The prime modulus.
	 * @param g The generator.
	 * @param h The public key component.
	 * @param additive Whether the key is used for additive homomorphism.
	 */
	public ElGamalPublicKey(BigInteger p, BigInteger g, BigInteger h, boolean additive) {
		this.p = p;
		this.g = g;
		this.h = h;
		this.additive = additive;
	}

	/**
	 * Sets whether the key is used for additive homomorphism.
	 *
	 * @param additive True if the key is additive, false otherwise.
	 */
	public void set_additive(boolean additive) {
		this.additive = additive;
	}

	/**
	 * Returns the algorithm name.
	 *
	 * @return The algorithm name ("ElGamal").
	 */
	public String getAlgorithm() {
		return "ElGamal";
	}

	/**
	 * Returns the format of the key.
	 *
	 * @return The format of the key ("X.509").
	 */
	public String getFormat() {
		return "X.509";
	}

	/**
	 * Returns the encoded form of the key.
	 *
	 * @return The encoded form of the key (currently null).
	 */
	public byte[] getEncoded() {
		return null;
	}

	/**
	 * Returns the prime modulus.
	 *
	 * @return The prime modulus.
	 */
	public BigInteger getP() {
		return this.p;
	}

	/**
	 * Returns a string representation of the ElGamal public key.
	 *
	 * @return A string representation of the key.
	 */
	public String toString() {
		String answer = "";
		answer += "p=" + this.p + '\n';
		answer += "g=" + this.g + '\n';
		answer += "h=" + this.h + '\n';
		return answer;
	}
}
