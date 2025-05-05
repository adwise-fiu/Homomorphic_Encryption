/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import javax.net.ssl.SSLSocket;

import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamal_Ciphertext;
import edu.fiu.adwise.homomorphic_encryption.gm.GMPublicKey;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKOperations;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKPrivateKey;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKPublicKey;

import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamalPublicKey;

import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierCipher;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierPublicKey;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The {@code alice} class represents Alice in the Socialist Millionaire's Problem.
 * It implements the {@code alice_interface} and extends {@code socialist_millionaires}.
 * This class provides methods for secure equality testing and other cryptographic operations
 * using homomorphic encryption techniques.
 * <p>
 * This specific class implements the first generation of encrypted comparison protocols
 */
public class alice extends socialist_millionaires implements alice_interface {

	private static final Logger logger = LogManager.getLogger(alice.class);

	/**
	 * Default constructor for the {@code alice} class.
	 * Initializes the {@code isDGK} flag to {@code false}.
	 */
	public alice() {
		this.isDGK = false;
	}

	/**
	 * Constructor for the {@code alice} class that accepts a client socket.
	 *
	 * @param clientSocket the client socket to communicate with Bob.
	 * @throws IOException if an I/O error occurs when setting up the socket.
	 * @throws NullPointerException if the provided {@code clientSocket} is {@code null}.
	 */
	public alice (Socket clientSocket) throws IOException {
		if(clientSocket != null) {
			set_socket(clientSocket);
		}
		else {
			throw new NullPointerException("Client Socket is null!");
		}
		this.isDGK = false;
	}

	/**
	 * Sets up the socket for communication with Bob using a standard {@code Socket}.
	 *
	 * @param socket the socket to communicate with Bob.
	 * @throws IOException if an I/O error occurs when setting up the socket.
	 */
	public void set_socket(Socket socket) throws IOException {
		toBob = new ObjectOutputStream(socket.getOutputStream());
		fromBob = new ValidatingObjectInputStream(socket.getInputStream());
		this.fromBob.accept(
				PaillierPublicKey.class,
				DGKPublicKey.class,
				ElGamalPublicKey.class,
				GMPublicKey.class,
				java.math.BigInteger.class,
				java.lang.Number.class,
				ElGamal_Ciphertext.class,
				java.util.HashMap.class,
				java.lang.Long.class,
				java.lang.String.class
		);
		this.fromBob.accept("[B");
		this.fromBob.accept("[L*");

		// Set TLS flag if the socket is an instance of SSLSocket
		if (socket instanceof SSLSocket) {
			this.tls_socket_in_use = true;
		}
	}

	/**
	 * Performs encrypted equality testing between two encrypted values {@code a} and {@code b}.
	 * Implements "Protocol 1 EQT-1" from the paper "Secure Equality Testing Protocols in the Two-Party Setting".
	 *
	 * @param a the first encrypted value.
	 * @param b the second encrypted value.
	 * @return {@code true} if the two values are equal, {@code false} otherwise.
	 * @throws HomomorphicException if a homomorphic encryption error occurs.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 */
	public boolean encrypted_equals(BigInteger a, BigInteger b) throws HomomorphicException, IOException, ClassNotFoundException {
		// Party A generates a sufficiently large (l + 1 + k bits) random
		// value r, computes [x] <- [a − b + r ], and sends [x] to B.
		BigInteger r;
		BigInteger x;

		if (isDGK) {
			x = DGKOperations.subtract(a, b, dgk_public);
			r = NTL.RandomBnd(dgk_public.getU());
			x = DGKOperations.add_plaintext(x, r, dgk_public);
		}
		else {
			x = PaillierCipher.subtract(a, b, paillier_public);
			r = NTL.RandomBnd(paillier_public.getN());
			x = PaillierCipher.add_plaintext(x, r, paillier_public);
		}
		writeObject(x);

		// Party B decrypts [x], computes the first l bits x_i, 0 ≤ i < l,
		// encrypts them separately with DGK (for efficiency reason), and
		// sends [x_i] to A.
		int delta_a = rnd.nextInt(2);

		// Technically, the whole computing delta_b and delta are already done here for you!
		// within the decrypt_protocol_one in private_equals()
		return private_equals(r, delta_a);
	}

	/**
	 * Performs an equality check as part of the encrypted equality testing protocol.
	 * This function is 'protected' as it is used by the public 'encrypted_equals' function
	 * @param r the random value used in the protocol.
	 * @param delta_a a random bit chosen by Alice.
	 * @return {@code true} if the two values are equal, {@code false} otherwise.
	 * @throws HomomorphicException if a homomorphic encryption error occurs.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 */
	protected boolean private_equals(BigInteger r, int delta_a) throws HomomorphicException, IOException, ClassNotFoundException {
		BigInteger [] Encrypted_Y = get_encrypted_bits();
        logger.info("Received Encrypted {} from bob for private_equals check", Encrypted_Y.length);
        BigInteger [] xor = encrypted_xor(r, Encrypted_Y);
		BigInteger [] C_a = new BigInteger[xor.length];
		BigInteger [] C_b = new BigInteger[xor.length];

		// Step 6: Sum XOR and multiply by random 2*t bit number
		C_a[0] = DGKOperations.sum(xor, dgk_public);
		BigInteger rho = NTL.generateXBitRandom(2 * dgk_public.getT());
		C_a[0] = DGKOperations.multiply(C_a[0], rho, dgk_public);

		// Step 7: Create lots of dummy encrypted numbers
		for (int i = 1; i < xor.length; i++) {
			C_a[i] = DGKOperations.encrypt(NTL.RandomBnd(dgk_public.getU()), dgk_public);
		}

		// Delta_B
		for (int i = 0; i < xor.length; i++) {
			// Sum XOR part and multiply by 2
			C_b[i] = DGKOperations.multiply(DGKOperations.sum(xor, dgk_public, i), 2, dgk_public);
			// subtract 1
			C_b[i] = DGKOperations.subtract(C_b[i], dgk_public.ONE(), dgk_public);
			// Add XOR bit value at i
			C_b[i] = DGKOperations.add(C_b[i], xor[i], dgk_public);
		}

		if (delta_a == 0) {
			shuffle_bits(C_a);
			writeObject(C_a);
		}
		else {
			shuffle_bits(C_b);
			writeObject(C_b);
		}

		// Bob just runs Protocol 1
		// I should note that decrypt protocol_one handles getting delta_b
		// and computing delta and decrypting delta
		return decrypt_protocol_one(delta_a);
	}

	/**
	 * Performs an equality check as part of the encrypted equality testing protocol.
	 * This function is 'protected' as it is used by the public 'encrypted_equals' function
	 * @param r the random value used in the protocol.
	 * @return {@code true} if the two values are equal, {@code false} otherwise.
	 * @throws HomomorphicException if a homomorphic encryption error occurs.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 */
	public boolean private_equals(BigInteger r) throws HomomorphicException, IOException, ClassNotFoundException {
		return private_equals(r, rnd.nextInt(2));
	}

	/**
	 * Computes the array of encrypted values \( C \) used in the secure comparison protocol.
	 * Each element \( C_i \) is calculated based on the XOR of the encrypted bits of \( x \) and \( y \),
	 * along with additional parameters such as \( \delta_a \).
	 *
	 * <p>The computation follows the formula:
	 * \( C_i = \text{sum}(XOR) + s + x_i - y_i \), where \( s \) is a function of \( \delta_a \).
	 * <p>
	 * This method is used in the context of the secure comparison protocol for both the original DGK
	 * comparison protocol and Veugen's approach
	 *
	 * @param x the plaintext value whose bits are compared.
	 * @param Encrypted_Y the array of encrypted bits of the second value \( y \).
	 * @param XOR the array of encrypted XOR results between the bits of \( x \) and \( y \).
	 * @param delta_a a random bit chosen by Alice for the protocol.
	 * @return an array of encrypted values \( C \), where the last element \( C_{-1} \) is a special sum.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	protected BigInteger [] compute_c(BigInteger x, BigInteger [] Encrypted_Y,
									  BigInteger [] XOR, int delta_a) throws HomomorphicException {

		BigInteger [] C = new BigInteger[XOR.length + 1];
		int xor_bit_length = XOR.length;
		int start_bit_position_x = Math.max(0, xor_bit_length - x.bitLength());
		int start_bit_position_y = Math.max(0, xor_bit_length - Encrypted_Y.length);

		// Compute the Product of XOR, add s and compute x - y
		// C_i = sum(XOR) + s + x_i - y_i
		for (int i = 0; i < XOR.length;i++) {
			// Retrieve corresponding bits from x and Encrypted_Y
			int x_bit = NTL.bit(x, i - start_bit_position_x);

			BigInteger y_bit;
			if (i >= start_bit_position_y) {
				y_bit = Encrypted_Y[i - start_bit_position_y];
			}
			else {
				y_bit = dgk_public.ZERO(); // If Encrypted_Y is shorter, treat the missing bits as zeros
			}

			C[i] = DGKOperations.multiply(DGKOperations.sum(XOR, dgk_public, i), 3, dgk_public);
			C[i] = DGKOperations.add_plaintext(C[i], 1 - 2L * delta_a, dgk_public);
			C[i] = DGKOperations.subtract(C[i], y_bit, dgk_public);
			C[i] = DGKOperations.add_plaintext(C[i], x_bit, dgk_public);
		}

		//This is c_{-1}
		C[XOR.length] = DGKOperations.sum(XOR, dgk_public);
		C[XOR.length] = DGKOperations.add_plaintext(C[XOR.length], delta_a, dgk_public);
		return C;
	}

	/**
	 * Executes Protocol 1 to securely compute whether {@code x <= y} in a two-party setting.
	 * This protocol uses homomorphic encryption to ensure privacy during the comparison.
	 *
	 * @param x the plaintext value to compare.
	 * @return {@code true} if {@code x <= y}, {@code false} otherwise.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws IllegalArgumentException if the bit length of X exceeds the limit defined by the DGK public key.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	public boolean Protocol1(BigInteger x)
			throws IOException, IllegalArgumentException, HomomorphicException, ClassNotFoundException {
		// Constraint...
		if(x.bitLength() > dgk_public.getL()) {
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + x.bitLength() + " bits");
		}

		int delta_a = rnd.nextInt(2);
		BigInteger [] Encrypted_Y = get_encrypted_bits();
		BigInteger [] C;
		BigInteger [] XOR;

		// Otherwise, if the bit size is equal, proceed!
		// Step 2: compute Encrypted X XOR Y
		XOR = encrypted_xor(x, Encrypted_Y);

		// Step 3: Alice picks deltaA and computes s 

		// Step 4: Compute C_i
		C = compute_c(x, Encrypted_Y, XOR, delta_a);

		// Step 5: Blinds C_i, Shuffle it and send to Bob
		for (int i = 0; i < C.length; i++) {
			C[i] = DGKOperations.multiply(C[i], rnd.nextInt(dgk_public.getU().intValue()) + 1, dgk_public);
		}
		C = shuffle_bits(C);
		writeObject(C);

		// Run Extra steps to help Alice decrypt Delta
		return decrypt_protocol_one(delta_a);
	}

	/**
	 * Executes Protocol 2 to securely compute whether X >= Y in a two-party setting.
	 * This protocol uses homomorphic encryption to ensure privacy during the comparison.
	 *
	 * @param x the encrypted value of X (Paillier or DGK encrypted).
	 * @param y the encrypted value of Y (Paillier or DGK encrypted).
	 * @return {@code true} if {@code x >= y}, {@code false} otherwise.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 * @throws IllegalArgumentException if the protocol is used with unsupported encryption schemes or invalid parameters.
	 */
	public boolean Protocol2(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException, HomomorphicException
	{
		Object bob;
		int deltaB;
		int deltaA = rnd.nextInt(2);
		int x_leq_y;
		BigInteger alpha_lt_beta;
		BigInteger z;
		BigInteger zdiv2L;
		BigInteger result;
		BigInteger r;
		BigInteger alpha;

		// Step 1: 0 <= r < N
		// Pick Number of l + 1 + sigma bits
		// Considering DGK is an option, stick with the size of Zu
		if (isDGK) {
			throw new IllegalArgumentException("Protocol 2 is NOT allowed with DGK! Used Protocol 4!");
		}
		else
		{
			// Generate Random Number with l + 1 + sigma bits
			if (dgk_public.getL() + SIGMA + 2 < paillier_public.key_size) {
				r = NTL.generateXBitRandom(dgk_public.getL() + 1 + SIGMA);
			}
			else {
				throw new IllegalArgumentException("Invalid due to constraint: l + sigma + 2 < log_2(N)!");
			}
		}

		/*
		 * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
		 * Send Z to Bob
		 * [[x + 2^l + r]]
		 * [[z]] = [[x - y + 2^l + r]]
		 */
		z = PaillierCipher.add_plaintext(x, r.add(powL).mod(paillier_public.getN()), paillier_public);
		z = PaillierCipher.subtract(z, y, paillier_public);
		writeObject(z);

		// Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

		// Step 3: alpha = r (mod 2^l)
		alpha = NTL.POSMOD(r, powL);

		// Step 4: Complete Protocol 1 or Protocol 3
		boolean P3 = Protocol1(alpha);
		if(P3) {
			x_leq_y = 1;
		}
		else {
			x_leq_y = 0;
		}

		// Step 5A: get Delta B
		// Step 5A: get Delta B
		deltaB = x_leq_y ^ deltaA;

		// Step 5B: Bob sends z/2^l 
		bob = readObject();
		if (bob instanceof BigInteger) {
			zdiv2L = (BigInteger) bob;
		}
		else {
			throw new IllegalArgumentException("Protocol 2, Step 5: z/2^l not found!");
		}

		// Step 6: Get [[beta < alpha]]
		if(deltaA == 1) {
			alpha_lt_beta = PaillierCipher.encrypt(deltaB, paillier_public);
		}
		else {
			alpha_lt_beta = PaillierCipher.encrypt(1 - deltaB, paillier_public);
		}

		// Step 7: get [[x <= y]]
		result = PaillierCipher.subtract(zdiv2L, PaillierCipher.encrypt(r.divide(powL), paillier_public), paillier_public);
		result = PaillierCipher.subtract(result, alpha_lt_beta, paillier_public);

		/*
		 * Unofficial Step 8:
		 * Since the result is encrypted...I need to send
		 * this back to Bob (Android Phone) to decrypt the solution...
		 * 
		 * Bob, by definition, would know the answer as well.
		 */
		return decrypt_protocol_two(result);
	}

	/**
	 * Please review Protocol 2 in the "Encrypted Integer Division" paper by Thjis Veugen
	 *
	 * @param x - Encrypted Paillier value or Encrypted DGK value
	 * @param d - plaintext divisor
	 * @throws IOException            - Any socket errors
	 * @throws HomomorphicException if the constraints {@code 0 <= x <= N * 2^(-sigma)} or {@code 0 <= d < N} are violated.
	 */
	public BigInteger division(BigInteger x, long d)
			throws IOException, ClassNotFoundException,  HomomorphicException {
		Object in;
		BigInteger answer;
		BigInteger c;
		BigInteger z;
		BigInteger r;

		int t = 0;
		
		// Step 1
		if(this.isDGK) {
			r = NTL.generateXBitRandom(dgk_public.getL() - 1).mod(dgk_public.getU());
			z = DGKOperations.add_plaintext(x, r, dgk_public);
			//N = dgk_public.bigU;
		}
		else {
			r = NTL.generateXBitRandom(paillier_public.key_size - 1).mod(paillier_public.getN());
			z = PaillierCipher.add_plaintext(x, r, paillier_public);
			//N = paillier_public.n;
		}
		writeObject(z);

		// Step 2: Executed by Bob
		
		// Step 3: Compute secure comparison Protocol
		if(!FAST_DIVIDE) {
			if (!Protocol1(r.mod(BigInteger.valueOf(d)))) {
				t = 1;
			}
		}
		
		// Step 4: Bob computes c and Alice receives it
		in = readObject();
		if (in instanceof BigInteger) {
			c = (BigInteger) in;
		}
		else {
			throw new IllegalArgumentException("Division: c is not found (Invalid Object): " + in.getClass().getName());
		}
		
		// Step 5: Alice computes [x/d]
		// [[z/d - r/d]]
		// [[z/d - r/d - t]]
		if (isDGK) {
			answer = DGKOperations.subtract_plaintext(c, r.divide(BigInteger.valueOf(d)), dgk_public);
			if(t == 1) {
				answer = DGKOperations.subtract_plaintext(answer, BigInteger.valueOf(t), dgk_public);
			}
		}
		else
		{
			answer = PaillierCipher.subtract_plaintext(c, r.divide(BigInteger.valueOf(d)), paillier_public);
			if(t == 1) {
				answer = PaillierCipher.subtract_plaintext(answer, BigInteger.valueOf(t), paillier_public);
			}
		}
		return answer;
	}

	/**
	 * See the paper "Correction of a Secure Comparison Protocol for Encrypted Integers in IEEE WIFS 2012
	 * (Short Paper)"
	 * Performs secure multiplication of two encrypted values using homomorphic encryption.
	 * This method ensures privacy by adding random blinding factors to the inputs before computation.
	 * The protocol involves communication with Bob to compute the product securely.
	 * by Mau et al.
	 * @param x the first encrypted value.
	 * @param y the second encrypted value.
	 * @return the encrypted result of the multiplication \( x \times y \).
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws IllegalArgumentException if the received object is not of the expected type.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	public BigInteger multiplication(BigInteger x, BigInteger y) 
			throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {
		Object in;
		BigInteger x_prime;
		BigInteger y_prime;
		BigInteger a;
		BigInteger b;
		BigInteger result;

		// Step 1
		if(isDGK) {
			a = NTL.RandomBnd(dgk_public.getU());
			b = NTL.RandomBnd(dgk_public.getU());
			x_prime = DGKOperations.add_plaintext(x, a, dgk_public);
			y_prime = DGKOperations.add_plaintext(y, b, dgk_public);
		}
		else {
			a = NTL.RandomBnd(paillier_public.getN());
			b = NTL.RandomBnd(paillier_public.getN());
			x_prime = PaillierCipher.add_plaintext(x, a, paillier_public);
			y_prime = PaillierCipher.add_plaintext(y, b, paillier_public);
		}
		// x' = x + a
		writeObject(x_prime);

		// y' = y + b
		writeObject(y_prime);

		// Step 2
		
		// Step 3
		in = readObject();
		if (in instanceof BigInteger) {
			// (x + a)(y + b) = xy + xb + ya + ab
			// xy = (x + a)(y + b) - xb - ya - ab
			result = (BigInteger) in;
			if(isDGK) {
				result = DGKOperations.subtract(result, DGKOperations.multiply(x, b, dgk_public), dgk_public);
				result = DGKOperations.subtract(result, DGKOperations.multiply(y, a, dgk_public), dgk_public);
				// To avoid throwing an exception to myself of encrypted range [0, U), mod it now!
				result = DGKOperations.subtract_plaintext(result, a.multiply(b).mod(dgk_public.getU()), dgk_public);
			}
			else {
				result = PaillierCipher.subtract(result, PaillierCipher.multiply(x, b, paillier_public), paillier_public);
				result = PaillierCipher.subtract(result, PaillierCipher.multiply(y, a, paillier_public), paillier_public);
				// To avoid throwing an exception to myself of encrypted range [0, N), mod it now!
				result = PaillierCipher.subtract_plaintext(result, a.multiply(b).mod(paillier_public.getN()), paillier_public);
			}
		}
		else {
			throw new IllegalArgumentException("Didn't get [[x' * y']] from Bob: " + in.getClass().getName());
		}
		return result;
	}

	/**
	 * Sets the DGK private key for Alice.
	 * This key is used for decryption and other operations in the DGK cryptosystem.
	 * You should NOT be using this function! This is only here to help with testing!
	 * Alice should never be getting Bob's private key!!!!
	 *
	 * @param dgk_private the DGK private key to be set.
	 */
	public void set_dgk_private_key(DGKPrivateKey dgk_private) {
		this.dgk_private = dgk_private;
	}

	/**
	 * Receives public keys from Bob and sets them for Alice.
	 * This method handles DGK, Paillier, and ElGamal public keys.
	 * If a specific key is not received, the corresponding field is set to null.
	 *
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 */
	public void receivePublicKeys()
			throws IOException, ClassNotFoundException {
		Object x;
		x = readObject();
		if (x instanceof DGKPublicKey) {
			logger.info("Alice Received DGK Public key from Bob");
			this.setDGKPublicKey((DGKPublicKey) x);
		}
		else {
			dgk_public = null;
		}
		
		x = readObject();
		if(x instanceof PaillierPublicKey) {
			logger.info("Alice Received Paillier Public key from Bob");
			this.setPaillierPublicKey((PaillierPublicKey) x);
		}
		else {
			paillier_public = null;
		}
	
		x = readObject();
		if(x instanceof ElGamalPublicKey) {
			logger.info("Alice Received ElGamal Public key from Bob");
			this.setElGamalPublicKey((ElGamalPublicKey) x);
		}
		else {
			el_gamal_public = null;
		}
	}


	/**
	 * Retrieves the k largest or smallest values from the input array using a bubble sort algorithm.
	 * The method can sort the entire array or only extract the k largest/smallest values.
	 *
	 * @param input the array of BigInteger values to process.
	 * @param k the number of values to retrieve.
	 * @param smallest_first if true, retrieves the k smallest values; otherwise, retrieves the k largest values.
	 * @return an array containing the k largest or smallest values.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws IllegalArgumentException if k is invalid or out of bounds.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	public BigInteger[] getKValues(BigInteger [] input, int k, boolean smallest_first)
			throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException
	{
		if(k > input.length || k <= 0) {
			throw new IllegalArgumentException("Invalid k value! " + k);
		}
		BigInteger [] arr = deep_copy(input);
		BigInteger [] sorted_k = new BigInteger[k];
		
		boolean activation;
		for (int i = 0; i < k; i++) {
			for (int j = 0; j < arr.length - 1 - i; j++) {
				writeBoolean(true);
				// Might need a K-Max test as well!
				activation = this.Protocol2(arr[j], arr[j + 1]);
				if (smallest_first) {
					activation = !activation;
				}
				
				// Originally arr[j] > arr[j + 1]
				if (activation) {
					// swap temp and arr[i]
					BigInteger temp = arr[j];
					arr[j] = arr[j + 1];
					arr[j + 1] = temp;
				}
			}
		}
		
		// Get last K-elements of arr!! 
		for (int i = 0; i < k; i++) {
			if (smallest_first) {
				sorted_k[i] = arr[arr.length - 1 - i];
			}
			else {
				sorted_k[k - 1 - i] = arr[arr.length - 1 - i];
			}
		}
		
		// Close Bob
		writeBoolean(false);
		return sorted_k;
	}

	/**
	 * Retrieves the k largest or smallest values from the input list using a bubble sort algorithm.
	 * The method can sort the entire list or only extract the k largest/smallest values.
	 * This operation involves secure comparisons using homomorphic encryption.
	 *
	 * @param input the list of BigInteger values to process.
	 * @param k the number of values to retrieve.
	 * @param smallest_first if true, retrieves the k smallest values; otherwise, retrieves the k largest values.
	 * @return an array containing the k largest or smallest values.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws IllegalArgumentException if k is invalid or out of bounds.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	public BigInteger[] getKValues(List<BigInteger> input, int k,  boolean smallest_first)
			throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException
	{
		if(k > input.size() || k <= 0) {
			throw new IllegalArgumentException("Invalid k value!");
		}
		// deep copy
		List<BigInteger> arr = new ArrayList<>(input);
		BigInteger [] sorted_k = new BigInteger[k];
		
		boolean activation;
		for (int i = 0; i < k; i++) {
			for (int j = 0; j < arr.size() - i - 1; j++) {
				writeBoolean(true);
				activation = this.Protocol2(arr.get(j), arr.get(j + 1));

				if(smallest_first) {
					activation = !activation;
				}
				
				// Originally arr[j] > arr[j + 1]
				if (activation) {
					// swap temp and arr[i]
					BigInteger temp = arr.get(j);
					arr.set(j, arr.get(j + 1));
					arr.set(j + 1, temp);
				}
			}
		}
		
		// Get last K-elements of arr!! 
		for (int i = 0; i < k; i++) {
			if (smallest_first) {
				sorted_k[i] = arr.get(arr.size() - 1 - i);
			}
			else {
				sorted_k[k - 1 - i] = arr.get(arr.size() - 1 - i);
			}
		}
		
		// Close Bob
		writeBoolean(false);
		return sorted_k;
	}
	
	// ---------------------- Everything here is essentially utility functions all Alice will need ----------------

	// Found the issue; i=0 should be a 0 on the smallest thing first no matter what.
	/**
	 * Computes the XOR operation between the bits of a plaintext value and an array of encrypted bits.
	 * The XOR operation is performed bit by bit, ensuring compatibility with homomorphic encryption.
	 * If the encrypted array is shorter than the plaintext value, missing bits are treated as zeros.
	 * <p>
	 * This is a function used for all versions of Alice
	 *
	 * @param x the plaintext value whose bits are XORed.
	 * @param Encrypted_Y the array of encrypted bits to XOR with the bits of {@code x}.
	 * @return an array of encrypted XOR results.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	public BigInteger [] encrypted_xor(BigInteger x, BigInteger [] Encrypted_Y) throws HomomorphicException {
		BigInteger [] xor_bits;
		int xor_bit_length;

		// Step 2: Determine the maximum bit length between x and Encrypted_Y
		xor_bit_length = Math.max(x.bitLength(), Encrypted_Y.length);

		// Step 2: Determine the starting bit position for x and Encrypted_Y
		int start_bit_position_x = Math.max(0, xor_bit_length - x.bitLength());
		int start_bit_position_y = Math.max(0, xor_bit_length - Encrypted_Y.length);

		// Remember a xor 0 = a
		xor_bits = new BigInteger[xor_bit_length];
		for (int i = 0; i < xor_bit_length; i++) {
			// Retrieve corresponding bits from x and Encrypted_Y
			int x_bit;
			BigInteger y_bit;
			x_bit = NTL.bit(x, i - start_bit_position_x);

			if (i >= start_bit_position_y) {
				y_bit = Encrypted_Y[i - start_bit_position_y];
			}
			else {
				y_bit = dgk_public.ZERO(); // If Encrypted_Y is shorter, treat the missing bits as zeros
			}

			if (dgk_private != null) {
                logger.debug("i={} x_bit is: {} and y_bit is: {}", i, x_bit, DGKOperations.decrypt(y_bit, dgk_private));
			}

			if (x_bit == 1) {
				xor_bits[i] = DGKOperations.subtract(dgk_public.ONE(), y_bit, dgk_public);
			}
			else {
				xor_bits[i] = y_bit;
			}
		}
		return xor_bits;
	}

	/**
	 * Retrieves an array of encrypted bits from Bob.
	 * This method reads an object from the input stream and validates that it is an array of {@code BigInteger}.
	 * <p>
	 * This is a function used for all versions of Alice
	 *
	 * @return an array of encrypted bits received from Bob.
	 * @throws HomomorphicException if the received object is not of the expected type.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 */
	protected BigInteger [] get_encrypted_bits() throws HomomorphicException, IOException, ClassNotFoundException {
		//Step 1: Receive y_i bits from Bob
		Object o = readObject();
		if (o instanceof BigInteger[]) {
			return (BigInteger []) o;
		}
		else {
			throw new HomomorphicException("Invalid Object received: " + o.getClass().getName());
		}
	}

	/**
	 * Executes the decryption protocol to securely compute the value of delta.
	 * This protocol involves receiving an encrypted value from Bob, performing computations
	 * based on the value of {@code delta_a}, and sending the result back to Bob.
	 * The protocol ensures that Alice and Bob can compute the result without revealing
	 * their private inputs.
	 * <p>
	 * This is a function used for all versions of Alice.
	 * Alice has delta_a, and Bob has delta_b, delta = delta_a XOR delta_b is equal to delta, the comparison result
	 * Alice wants to get delta without revealing delta_a, hence the blinding step.
	 *
	 * @param delta_a a random bit chosen by Alice for the protocol.
	 * @return {@code true} if the computed delta equals 1, {@code false} otherwise.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws ClassNotFoundException if a class cannot be found during deserialization.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	protected boolean decrypt_protocol_one(int delta_a) throws IOException, ClassNotFoundException, HomomorphicException {
		Object o;
		BigInteger delta;
		BigInteger blind = BigInteger.ZERO;

		// Step 6: Bob looks for any 0's in C_i and computes DeltaB

		// Step 7: Obtain Delta B from Bob
		// Party B encrypts delta_B using his public key and sends it to Alice. Upon receiving
		// delta_B, party A computes the encryption of delta as
		// 1- delta = delta_b if delta_a = 0
		// 2- delta = 1 - delta_b otherwise if delta_a = 1.
		o = readObject();
		if (o instanceof BigInteger) {
			if (delta_a == 0) {
				delta = (BigInteger) o;
			}
			else {
				delta = DGKOperations.subtract(dgk_public.ONE(), (BigInteger) o, dgk_public);
			}
		}
		else {
			throw new HomomorphicException("Invalid Object found here: " + o.getClass().getName());
		}

		/*
		 * Step 8: Bob has the Private key anyway
		 * Send him the encrypted answer!
		 * Alice and Bob know now without revealing x or y!
		 *
		 * You can blind it for safety, but I will assume Bob is nice,
		 * Plus the info doesn't really reveal anything to Bob.
		 */
		// Blind = NTL.RandomBnd(dgk_public.getU());
		writeObject(DGKOperations.add_plaintext(delta, blind, dgk_public));

		o = readObject();
		if (o instanceof BigInteger) {
			delta = (BigInteger) o;
			delta = delta.subtract(blind);
			return delta.equals(BigInteger.ONE);
		}
		else {
			throw new HomomorphicException("Invalid Object found here: " + o.getClass().getName());
		}
	}

	/**
	 * Executes the decryption protocol to securely determine the result of an encrypted inequality.
	 * This protocol involves sending the encrypted result to Bob for decryption and receiving
	 * the comparison result. The protocol ensures that Alice and Bob can compute the result
	 * without revealing their private inputs.
	 *
	 * @param result the encrypted result of the inequality.
	 * @return {@code true} if the comparison result is {@code x >= y}, {@code false} otherwise.
	 * @throws IOException if an I/O error occurs during communication.
	 * @throws HomomorphicException if an error occurs during homomorphic operations.
	 */
	protected boolean decrypt_protocol_two(BigInteger result) throws IOException, HomomorphicException {
		BigInteger blind = BigInteger.ZERO;
		// blind = NTL.RandomBnd(dgk_public.getU());

		// I reserve the right to additively blind,
		// But like in decrypt_protocol_one, I will assume Bob is nice
		if (isDGK) {
			result = DGKOperations.add_plaintext(result, blind, dgk_public);
		}
		else {
			result = PaillierCipher.add_plaintext(result, blind, paillier_public);
		}
		writeObject(result);

		int comparison = fromBob.readInt();// x <= y
		// IF SOMETHING HAPPENS...GET THE POST MORTEM HERE
		if (comparison != 0 && comparison != 1) {
			throw new IllegalArgumentException("Invalid Comparison output! --> " + comparison);
		}
		return comparison == 1;
	}
}
