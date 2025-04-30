/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import javax.net.ssl.SSLSocket;

import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamal_Ciphertext;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKOperations;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKPrivateKey;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKPublicKey;
import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamalPrivateKey;
import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamalPublicKey;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierCipher;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierPublicKey;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierPrivateKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The {@code bob} class represents Bob in the Socialist Millionaire's Problem.
 * It implements the {@code bob_interface} and extends {@code socialist_millionaires}.
 * This class provides methods for secure equality testing and other cryptographic operations
 * using homomorphic encryption techniques.
 * <p>
 * This specific class implements the first generation of encrypted comparison protocols
 */
public class bob extends socialist_millionaires implements bob_interface
{
	private static final Logger logger = LogManager.getLogger(bob.class);

	/**
	 * Constructs a Bob instance with three key pairs.
	 *
	 * @param first the first key pair (Paillier or DGK).
	 * @param second the second key pair (DGK or Paillier).
	 * @param third the third key pair (ElGamal), optional.
	 */
	public bob(KeyPair first, KeyPair second, KeyPair third) {
		parse_key_pairs(first, second, third);
	}

	/**
	 * Constructs a Bob instance with two key pairs.
	 *
	 * @param first the first key pair (Paillier or DGK).
	 * @param second the second key pair (DGK or Paillier).
	 */
	public bob(KeyPair first, KeyPair second) {
		parse_key_pairs(first, second, null);
	}


	/**
	 * Parses and assigns the provided key pairs to the appropriate cryptographic schemes.
	 *
	 * @param first the first key pair (Paillier or DGK).
	 * @param second the second key pair (DGK or Paillier).
	 * @param third the third key pair (ElGamal), optional.
	 * @throws IllegalArgumentException if the key pairs are not valid or mismatched.
	 */
	private void parse_key_pairs(KeyPair first, KeyPair second, KeyPair third) {
		if (first.getPublic() instanceof PaillierPublicKey) {
			this.paillier_public = (PaillierPublicKey) first.getPublic();
			this.paillier_private = (PaillierPrivateKey) first.getPrivate();
			if(second.getPublic() instanceof DGKPublicKey) {
				this.dgk_public = (DGKPublicKey) second.getPublic();
				this.dgk_private = (DGKPrivateKey) second.getPrivate();
			}
			else {
				throw new IllegalArgumentException("Obtained Paillier Key Pair, Not DGK Key pair!");
			}
		}
		else if (first.getPublic() instanceof DGKPublicKey) {
			this.dgk_public = (DGKPublicKey) first.getPublic();
			this.dgk_private = (DGKPrivateKey) first.getPrivate();
			if (second.getPublic() instanceof PaillierPublicKey) {
				this.paillier_public = (PaillierPublicKey) second.getPublic();
				this.paillier_private = (PaillierPrivateKey) second.getPrivate();
			}
			else {
				throw new IllegalArgumentException("Obtained DGK Key Pair, Not Paillier Key pair!");
			}
		}

		if(third != null) {
			if (third.getPublic() instanceof ElGamalPublicKey) {
				this.el_gamal_public = (ElGamalPublicKey) third.getPublic();
				this.el_gamal_private= (ElGamalPrivateKey) third.getPrivate();
			}
			else {
				throw new IllegalArgumentException("Third Keypair MUST BE AN EL GAMAL KEY PAIR!");
			}
		}

		this.isDGK = false;
		powL = TWO.pow(dgk_public.getL());
	}

	/**
	 * Sets the socket for communication with Alice.
	 *
	 * @param socket the socket to use for communication.
	 * @throws IOException if an I/O error occurs.
	 * @throws NullPointerException if the provided socket is null.
	 */
	public void set_socket(Socket socket) throws IOException {
		this.toAlice = new ObjectOutputStream(socket.getOutputStream());
		this.fromAlice = new ValidatingObjectInputStream(socket.getInputStream());
		this.fromAlice.accept(
				java.math.BigInteger.class,
				java.lang.Number.class,
				java.util.HashMap.class,
				java.lang.Long.class,
				ElGamal_Ciphertext.class,
				java.lang.String.class
		);
		this.fromAlice.accept("[B");
		this.fromAlice.accept("[L*");

		// Set TLS flag if the socket is an instance of SSLSocket
		if (socket instanceof SSLSocket) {
			this.tls_socket_in_use = true;
		}
	}

	/**
	 * Sorts a list of encrypted numbers using Protocol 2.
	 * This method repeatedly invokes Protocol 2 until the sorting is complete.
	 *
	 * @throws IOException if an I/O error occurs.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	public void sort()
			throws IOException, ClassNotFoundException, HomomorphicException {
		long start_time = System.nanoTime();
		int counter = 0;
		while(readBoolean()) {
			++counter;
			this.Protocol2();
		}
        logger.info("Protocol 2 was used {} times!", counter);
        logger.info("Protocol 2 completed in {} seconds!", (System.nanoTime() - start_time) / BILLION);
	}

	/**.
	 * Review "Protocol 1 EQT-1" from the paper "Secure Equality Testing Protocols in the Two-Party Setting"
	 *
	 * @throws IOException if an I/O error occurs.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 */
	public void encrypted_equals() throws IOException, HomomorphicException, ClassNotFoundException {
		// Receive x from Alice
		Object o = readObject();
		BigInteger y;
		if (o instanceof BigInteger) {
			y = (BigInteger) o;
		}
		else {
			throw new HomomorphicException("In encrypted_equals(), I did NOT get a BigInteger");
		}
		// Decrypt x to use private comparison
		if (isDGK) {
			y = BigInteger.valueOf(DGKOperations.decrypt(y, dgk_private));
		}
		else {
			y = PaillierCipher.decrypt(y, paillier_private);
		}
		// Technically, the whole computing delta_b and delta are already done here for you!
		// within the decrypt_protocol_one in private_equals()
		Protocol1(y);
	}

	/**
	 * Encrypts the bits of a given plaintext value.
	 *
	 * @param y the plaintext value to encrypt.
	 * @return an array of encrypted bits.
	 */
	public BigInteger [] encrypt_bits(BigInteger y) throws HomomorphicException {
		BigInteger [] Encrypted_Y = new BigInteger[y.bitLength()];
		for (int i = 0; i < y.bitLength(); i++) {
			Encrypted_Y[i] = DGKOperations.encrypt(NTL.bit(y, i), dgk_public);
		}
		return Encrypted_Y;
	}

	/**
	 * Computes the delta value (deltaB) for Bob based on the decrypted values in C.
	 *
	 * @param C the array of encrypted values.
	 * @return the computed delta value (deltaB).
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	public int compute_delta_b(BigInteger [] C) throws HomomorphicException {
		int deltaB = 0;
		for (BigInteger C_i : C) {
			long value = DGKOperations.decrypt(C_i, dgk_private);
			if (value == 0) {
				deltaB = 1;
			}
		}
		return deltaB;
	}

	/**
	 * Please review "Improving the DGK comparison protocol" - Protocol 1
	 * Nicely enough; this is the same thing Bob needs to do for Veugen, Joye and checking
	 * if two encrypted numbers are equal!
	 * This is the original protocol from DGK, the improved versions are in alice_veugen.
	 * This protocol allows Bob to securely compare encrypted values with Alice
	 * and determine equality without revealing the plaintext values.
	 *
	 * @param y the plaintext value to compare.
	 * @return {@code true} if the comparison result indicates equality, {@code false} otherwise.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws IllegalArgumentException if {@code y} has more bits than supported by the DGK keys.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	public boolean Protocol1(BigInteger y)
			throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {
		Object o;
		BigInteger [] C;
		BigInteger temp;
		int deltaB;

		// Step 1: Bob sends encrypted bits to Alice
        logger.debug("[private_integer_comparison] Bob is sending {}", y);
        logger.info("[private_integer_comparison] I am comparing sending y, which is {} bits long", y.bitLength());
		writeObject(encrypt_bits(y));

		// Step 2: Alice...
		// Step 3: Alice...
		// Step 4: Alice...
		// Step 5: Alice...
		// Step 6: Check if one of the numbers in C_i is decrypted to 0.
		o = readObject();
		if(o instanceof BigInteger[]) {
			C = (BigInteger []) o;
		}
		else if (o instanceof BigInteger) {
			temp = (BigInteger) o;
			if (temp.equals(BigInteger.ONE)) {
				return true;
			}
			else if (temp.equals(BigInteger.ZERO)) {
				return false;
			}
			else {
				throw new IllegalArgumentException("This shouldn't be possible...");
			}
		}
		else {
			throw new IllegalArgumentException("Protocol 1, Step 6: Invalid object: " + o.getClass().getName());
		}

		// Perform constant-time comparison to update delta_b
		deltaB = compute_delta_b(C);

		// Run Extra steps to help Alice decrypt Delta
		return decrypt_protocol_one(deltaB);
	}

	/**
	 * Executes the decryption protocol for deltaB.
	 * This protocol allows Bob to securely send deltaB to Alice and receive the result.
	 *
	 * @param deltaB the delta value computed by Bob.
	 * @return {@code true} if the decrypted result equals 1, {@code false} otherwise.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	protected boolean decrypt_protocol_one(int deltaB) throws IOException, ClassNotFoundException, HomomorphicException {
		Object o;
		BigInteger delta;

		// Step 7: UNOFFICIAL
		// Inform Alice what deltaB is

		// Party B encrypts delta_B using his public key and sends it to Alice. Upon receiving
		// delta_B, party A computes the encryption of delta as
		// 1- delta = delta_b if delta_a = 0
		// 2- delta = 1 - delta_b otherwise if delta_a = 1.
		writeObject(DGKOperations.encrypt(deltaB, dgk_public));

		// Step 8: UNOFFICIAL
		// Alice sends the encrypted answer...
		// For now, Bob doesn't need to know the decryption, so Alice did blind it.
		// So decrypt and return the value.
		o = fromAlice.readObject();
		if (o instanceof BigInteger) {
			delta = BigInteger.valueOf(DGKOperations.decrypt((BigInteger) o, dgk_private));
			writeObject(delta);
			return delta.equals(BigInteger.ONE);
		}
		else {
			throw new IllegalArgumentException("Invalid response from Alice in Step 8: " + o.getClass().getName());
		}
	}

	/**
	 * Executes the decryption protocol for comparison results.
	 * This protocol allows Bob to decrypt the comparison result sent by Alice.
	 *
	 * @return {@code true} if the comparison result indicates {@code x >= y}, {@code false} otherwise.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	protected boolean decrypt_protocol_two() throws IOException, ClassNotFoundException, HomomorphicException {
		Object x;
		int answer = -1;

		x = fromAlice.readObject();
		if (x instanceof BigInteger) {
			if(isDGK) {
				long decrypt = DGKOperations.decrypt((BigInteger) x, dgk_private);
				// IF SOMETHING HAPPENS...GET TO POST MORTEM HERE
				if (decrypt != 0 && dgk_public.getU().longValue() - 1 != decrypt) {
					throw new IllegalArgumentException("Invalid Comparison result --> " + answer);
				}

				if (dgk_public.getu() - 1 == decrypt) {
					answer = 0;
				}
				else {
					answer = 1;
				}
			}
			else {
				answer = PaillierCipher.decrypt((BigInteger) x, paillier_private).intValue();
			}
			writeInt(answer);

		}
		else {
			throw new IllegalArgumentException("Protocol 4, Step 8 Failed " + x.getClass().getName());
 		}
		// IF SOMETHING HAPPENS...GET TO POST MORTEM HERE
		if (answer != 0 && answer != 1) {
			throw new IllegalArgumentException("Invalid Comparison result --> " + answer);
		}
		return answer == 1;
	}

	/**
	 * Please review "Improving the DGK comparison protocol" - Protocol 2
	 * Executes Protocol 2 for secure comparison.
	 * This protocol allows Bob to securely compare encrypted values with Alice.
	 * This uses the original comparison protocol from DGK, the improved versions are in alice_veugen and alice_joye.
	 *
	 * @return {@code true} if the comparison result indicates {@code x >= y}, {@code false} otherwise.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	public boolean Protocol2()
			throws ClassNotFoundException, IOException, HomomorphicException {
		// Step 1: Receive z from Alice
		// Get the input and output streams
		Object x;
		BigInteger beta;
		BigInteger z;
		
		if(isDGK) {
			throw new HomomorphicException("COMPARING ENCRYPTED DGK VALUES WITH PROTOCOL 2 IS NOT ALLOWED," +
					" PLEASE USE PROTOCOL 4!");
		}

		//Step 1: get [[z]] from Alice
		x = fromAlice.readObject();
		if (x instanceof BigInteger) {
			z = (BigInteger) x;
		}
		else {
			throw new IllegalArgumentException("Bob Step 1: Invalid Object!" + x.getClass().getName());
		}
		
		//[[z]] = [[x - y + 2^l + r]]
		z = PaillierCipher.decrypt(z, paillier_private);
		
		// Step 2: compute Beta = z (mod 2^l),
		beta = NTL.POSMOD(z, powL);
		
		// Step 3: Alice computes r (mod 2^l) (Alpha)
		// Step 4: Run Protocol 3
		Protocol1(beta);
		
		// Step 5: Send [[z/2^l]], Alice has the solution from Protocol 3 already...
		writeObject(PaillierCipher.encrypt(z.divide(powL), paillier_public));
		
		// Step 6 - 7: Alice Computes [[x >= y]]
		
		// Step 8 (UNOFFICIAL): Alice needs the answer for [[x >= y]]
		return decrypt_protocol_two();
	}


	/**
	 *  See the paper "Correction of a Secure Comparison Protocol for Encrypted Integers in IEEE WIFS 2012
	 * 	(Short Paper)"
	 * This performs secure multiplication of two encrypted values.
	 * This method decrypts the values, performs multiplication, and re-encrypts the result, but the results are blinded by Alice,
	 * so Bob should not be aware what the actual product is.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	public void multiplication() 
			throws IOException, ClassNotFoundException, HomomorphicException
	{
		Object in;
		BigInteger x_prime;
		BigInteger y_prime;
		
		// Step 2
		in = fromAlice.readObject();
		if(in instanceof BigInteger) {
			x_prime = (BigInteger) in;
		}
		else {
			throw new IllegalArgumentException("Didn't get [[x']] from Alice: " + in.getClass().getName());
		}
		
		in = fromAlice.readObject();
		if(in instanceof BigInteger) {
			y_prime = (BigInteger) in;
		}
		else {
			throw new IllegalArgumentException("Didn't get [[y']] from Alice: " + in.getClass().getName());		
		}
		
		// Step 3
		if(isDGK) {
			x_prime = BigInteger.valueOf(DGKOperations.decrypt(x_prime, dgk_private));
			y_prime = BigInteger.valueOf(DGKOperations.decrypt(y_prime, dgk_private));
			// To avoid myself throwing errors of encryption must be [0, U), mod it now!
			writeObject(DGKOperations.encrypt(x_prime.multiply(y_prime).mod(dgk_public.getU()), dgk_public));
		}
		else {
			x_prime = PaillierCipher.decrypt(x_prime, paillier_private);
			y_prime = PaillierCipher.decrypt(y_prime, paillier_private);
			// To avoid myself throwing errors of encryption must be [0, N), mod it now!
			writeObject(PaillierCipher.encrypt(x_prime.multiply(y_prime).mod(paillier_public.getN()), paillier_public));
		}
	}

	/**
	 * Please review Protocol 2 in the "Encrypted Integer Division" paper by Thjis Veugen
	 * Performs secure division of an encrypted value received from Alice by a given divisor.
	 * The result is encrypted and sent back to Alice. Bob does not learn the plaintext result.
	 *
	 * @param divisor the divisor to divide the encrypted value by.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 * @throws IllegalArgumentException if the received object is not a {@code BigInteger}.
	 */
	public void division(long divisor) 
			throws ClassNotFoundException, IOException, HomomorphicException
	{
		BigInteger c;
		BigInteger z;
		Object alice = fromAlice.readObject();
		if(alice instanceof BigInteger)	{
			z = (BigInteger) alice;
		}
		else {
			throw new IllegalArgumentException("Division: No BigInteger found: " + alice.getClass().getName());
		}
		
		if(isDGK) {
			z = BigInteger.valueOf(DGKOperations.decrypt(z, dgk_private));
		}
		else {
			z = PaillierCipher.decrypt(z, paillier_private);
		}
		
		if(!FAST_DIVIDE) {
			Protocol1(z.mod(BigInteger.valueOf(divisor)));
		}
		// MAYBE IF OVERFLOW HAPPENING?
		// Modified_Protocol3(z.mod(powL), z);	
	
		c = z.divide(BigInteger.valueOf(divisor));

		if(isDGK) {
			c = DGKOperations.encrypt(c, dgk_public);
		}
		else {
			c = PaillierCipher.encrypt(c, paillier_public);
		}
		writeObject(c);
		/*
		 *  Unlike Comparison, it is decided Bob shouldn't know the answer.
		 *  This is because Bob KNOWS d, and can decrypt [x/d]
		 *  
		 *  Since the idea is not to leak the numbers themselves,
		 *  it is decided Bob shouldn't receive [x/d]
		 */
	}

	/**
	 * Sends Bob's public keys (DGK, Paillier, and ElGamal) to Alice.
	 * If a key is not available, a placeholder value of {@code BigInteger.ZERO} is sent instead.
	 *
	 * @throws IOException if an I/O error occurs during communication.
	 */
	public void sendPublicKeys() throws IOException
	{
		if(dgk_public != null) {
			writeObject(dgk_public);
			logger.info("Bob sent DGK Public Key to Alice");
		}
		else {
			writeObject(BigInteger.ZERO);
		}
		if(paillier_public != null) {
			writeObject(paillier_public);
			logger.info("Bob sent Paillier Public Key to Alice");
		}
		else {
			writeObject(BigInteger.ZERO);
		}
		if(el_gamal_public != null) {
			writeObject(el_gamal_public);
			logger.info("Bob sent ElGamal Public Key to Alice");
		}
		else {
			writeObject(BigInteger.ZERO);
		}
		toAlice.flush();
	}
}