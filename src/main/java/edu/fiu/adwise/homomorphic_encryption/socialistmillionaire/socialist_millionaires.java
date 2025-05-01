/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import edu.fiu.adwise.homomorphic_encryption.dgk.DGKPrivateKey;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKPublicKey;
import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamalPrivateKey;
import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamalPublicKey;
import edu.fiu.adwise.homomorphic_encryption.misc.CipherConstants;
import edu.fiu.adwise.homomorphic_encryption.misc.InstrumentationAgent;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierPrivateKey;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierPublicKey;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

/**
 * Abstract class representing the Socialist Millionaires' Problem (SMP) protocol.
 * This class provides the base implementation for secure multi-party computation
 * using homomorphic encryption techniques.
 * <p>
 * It includes methods for managing cryptographic keys, performing I/O operations,
 * and utility functions for encrypted data manipulation.
 */
public abstract class socialist_millionaires implements CipherConstants
{
	/** Tracks the total number of bytes sent during communication. */
	protected long bytes_sent = 0;

	/** Secure random number generator for cryptographic operations. */
	protected static final SecureRandom rnd = new SecureRandom();

	/** Security parameter for cryptographic operations. */
	protected final static int SIGMA = 80;

	/** Flag to enable or disable fast division optimization. */
	protected boolean FAST_DIVIDE = false;

	/** Flag to indicate if DGK encryption mode is enabled. */
	protected boolean isDGK = false;

	// Cryptographic keys for Alice and Bob
	/** The Paillier public key used for encryption and decryption operations. */
	protected PaillierPublicKey paillier_public = null;

	/** The DGK public key used for DGK encryption and decryption operations. */
	protected DGKPublicKey dgk_public = null;

	/** The ElGamal public key used for ElGamal encryption and decryption operations. */
	protected ElGamalPublicKey el_gamal_public = null;

	// Private keys for cryptographic operations
	/** The Paillier private key used for decryption operations. */
	protected PaillierPrivateKey paillier_private = null;

	/** The DGK private key used for DGK decryption operations. */
	protected DGKPrivateKey dgk_private = null;

	/** The ElGamal private key used for ElGamal decryption operations. */
	protected ElGamalPrivateKey el_gamal_private = null;

	/** Precomputed value of 2^l for DGK encryption. */
	protected BigInteger powL;

	// I/O streams for communication between Alice and Bob
	/** The output stream for sending objects to Bob. */
	protected ObjectOutputStream toBob = null;

	/** The input stream for receiving validated objects from Bob. */
	protected ValidatingObjectInputStream fromBob = null;

	/** The output stream for sending objects to Alice. */
	protected ObjectOutputStream toAlice = null;

	/** The input stream for receiving validated objects from Alice. */
	protected ValidatingObjectInputStream fromAlice = null;

	/** Indicates if TLS sockets are used for secure communication. */
	protected boolean tls_socket_in_use = false;

	/**
	 * Sets the DGK encryption mode.
	 *
	 * @param isDGK true to enable DGK mode, false otherwise.
	 */
	public void setDGKMode(boolean isDGK) {
		this.isDGK = isDGK;
	}

	/**
	 * Checks if DGK encryption mode is enabled.
	 *
	 * @return true if DGK mode is enabled, false otherwise.
	 */
	public boolean isDGK() {
		return isDGK;
	}

	/**
	 * Sets the Paillier public key.
	 *
	 * @param paillier_public the Paillier public key.
	 */
	public void setPaillierPublicKey(PaillierPublicKey paillier_public) {
		this.paillier_public = paillier_public;
	}

	/**
	 * Sets the DGK public key and precomputes 2^l.
	 *
	 * @param dgk_public the DGK public key.
	 */
	public void setDGKPublicKey(DGKPublicKey dgk_public) {
		this.dgk_public = dgk_public;
		this.powL = TWO.pow(this.dgk_public.getL());
	}

	/**
	 * Sets the ElGamal public key.
	 *
	 * @param el_gamal_public the ElGamal public key.
	 */
	public void setElGamalPublicKey(ElGamalPublicKey el_gamal_public) {
		this.el_gamal_public = el_gamal_public;
	}

	/**
	 * Retrieves the Paillier public key.
	 *
	 * @return the Paillier public key.
	 */
	public PaillierPublicKey getPaillierPublicKey() {
		return paillier_public;
	}

	/**
	 * Retrieves the DGK public key.
	 *
	 * @return the DGK public key.
	 */
	public DGKPublicKey getDGKPublicKey() {
		return dgk_public;
	}

	/**
	 * Retrieves the ElGamal public key.
	 *
	 * @return the ElGamal public key.
	 */
	public ElGamalPublicKey getElGamalPublicKey() {
		return el_gamal_public;
	}

	/**
	 * Retrieves the total number of bytes sent during communication.
	 *
	 * @return the total bytes sent.
	 */
	public long get_bytes_sent() {
		return this.bytes_sent;
	}

	/**
	 * Reads a boolean value from the input stream.
	 *
	 * @return the boolean value read.
	 * @throws IOException if an I/O error occurs.
	 */
	public boolean readBoolean() throws IOException {
		if(fromBob != null) {
			return fromBob.readBoolean();
		}
		else {
			return fromAlice.readBoolean();
		}
	}

	/**
	 * Writes a boolean value to the output stream.
	 *
	 * @param value the boolean value to write.
	 * @throws IOException if an I/O error occurs.
	 */
	public void writeBoolean(boolean value) throws IOException {
		bytes_sent += 4;
		if(toBob != null) {
			toBob.writeBoolean(value);
			toBob.flush();
		}
		else {
			toAlice.writeBoolean(value);
			toAlice.flush();
		}
	}

	/**
	 * Reads an integer value from the input stream.
	 *
	 * @return the integer value read.
	 * @throws IOException if an I/O error occurs.
	 */
	public int readInt() throws IOException {
		if (fromBob != null) {
			return fromBob.readInt();
		}
		else {
			return fromAlice.readInt();
		}
	}

	/**
	 * Writes an integer value to the output stream.
	 *
	 * @param value the integer value to write.
	 * @throws IOException if an I/O error occurs.
	 */
	public void writeInt(int value) throws IOException {
		bytes_sent += 4;
		if (toBob != null) {
			toBob.writeInt(value);
			toBob.flush();
		}
		else {
			toAlice.writeInt(value);
			toAlice.flush();
		}
	}

	/**
	 * Reads an object from the input stream.
	 *
	 * @return the object read.
	 * @throws IOException if an I/O error occurs.
	 * @throws ClassNotFoundException if the class of the object cannot be found.
	 */
	public Object readObject() throws IOException, ClassNotFoundException {
		if(fromBob != null) {
			return fromBob.readObject();
		}
		else {
			return fromAlice.readObject();
		}
	}

	/**
	 * Writes an object to the output stream.
	 *
	 * @param o the object to write.
	 * @throws IOException if an I/O error occurs.
	 */
	public void writeObject(Object o) throws IOException {
		try {
			bytes_sent += InstrumentationAgent.getObjectSize(o);
		}
		catch (IllegalStateException ignored) {

		}

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
	 * Creates a deep copy of a BigInteger array.
	 *
	 * @param input the input array to copy.
	 * @return a deep copy of the input array.
	 */
	protected BigInteger [] deep_copy(BigInteger [] input) {
		BigInteger [] copy = new BigInteger[input.length];
		System.arraycopy(input, 0, copy, 0, input.length);
		return copy;
	}

	/**
	 * Shuffles the elements of a BigInteger array in place.
	 * Note: This method does not create a new array.
	 *
	 * @param array the array to shuffle.
	 * @return the shuffled array.
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
