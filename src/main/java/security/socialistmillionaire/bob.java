package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import javax.net.ssl.SSLSocket;

import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import security.dgk.DGKOperations;
import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;
import security.paillier.PaillierPrivateKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class bob extends socialist_millionaires implements bob_interface
{
	private static final Logger logger = LogManager.getLogger(bob.class);

	public bob(KeyPair first, KeyPair second, KeyPair third) {
		parse_key_pairs(first, second, third);
	}

	public bob(KeyPair first, KeyPair second) {
		parse_key_pairs(first, second, null);
	}

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

	public void set_socket(Socket socket) throws IOException {
		if(socket != null) {
			this.toAlice = new ObjectOutputStream(socket.getOutputStream());
			this.fromAlice = new ValidatingObjectInputStream(socket.getInputStream());
			this.fromAlice.accept(
					java.math.BigInteger.class,
					java.lang.Number.class,
					java.util.HashMap.class,
					java.lang.Long.class,
					security.elgamal.ElGamal_Ciphertext.class,
					java.lang.String.class
			);
			this.fromAlice.accept("[B");
			this.fromAlice.accept("[L*");
		}
		else {
			throw new NullPointerException("Client Socket is null!");
		}
	}

	public void set_socket(SSLSocket socket) throws IOException {
		if(socket != null) {
			this.toAlice = new ObjectOutputStream(socket.getOutputStream());
			this.fromAlice = new ValidatingObjectInputStream(socket.getInputStream());
			this.fromAlice.accept(
					java.math.BigInteger.class,
					java.lang.Number.class,
					java.util.HashMap.class,
					java.lang.Long.class,
					security.elgamal.ElGamal_Ciphertext.class,
					java.lang.String.class
			);
			this.fromAlice.accept("[B");
			this.fromAlice.accept("[L*");
		}
		else {
			throw new NullPointerException("Client Socket is null!");
		}
		this.tls_socket_in_use = true;
	}

	/**
	 * if Alice wants to sort a list of encrypted numbers, use this method if you 
	 * will consistently sort using Protocol 2
	 */
	public void sort()
			throws IOException, ClassNotFoundException, HomomorphicException {
		long start_time = System.nanoTime();
		int counter = 0;
		while(readBoolean()) {
			++counter;
			this.Protocol2();
		}
		logger.info("Protocol 2 was used " + counter + " times!");
		logger.info("Protocol 2 completed in " + (System.nanoTime() - start_time)/BILLION + " seconds!");
	}
	
	/*
	 * Review "Protocol 1 EQT-1"
	 * from the paper "Secure Equality Testing Protocols in the Two-Party Setting"
	 */
	public boolean encrypted_equals() throws IOException, HomomorphicException, ClassNotFoundException {
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
		return Protocol1(y);
	}

	/**
	 * Please review "Improving the DGK comparison protocol" - Protocol 1
	 * Nicely enough, this is the same thing Bob needs to do for Veugen, Joye and checking 
	 * if two encrypted numbers are equal!
	 *
	 * @param y - plaintext value
	 * @return boolean
	 * @throws IllegalArgumentException - if y has more bits than is supported by provided DGK keys
	 */
	public boolean Protocol1(BigInteger y)
			throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {
		Object o;
		int deltaB = 0;
		BigInteger [] C;
		BigInteger temp;

		// Step 1: Bob sends encrypted bits to Alice
		BigInteger [] EncY = new BigInteger[y.bitLength()];
		for (int i = 0; i < y.bitLength(); i++) {
			EncY[i] = DGKOperations.encrypt(NTL.bit(y, i), dgk_public);
		}
		writeObject(EncY);
		
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
		for (BigInteger C_i : C) {
			long value = DGKOperations.decrypt(C_i, dgk_private);
			if (value == 0) {
				deltaB = 1;
			}
		}

		// Run Extra steps to help Alice decrypt Delta
		return decrypt_protocol_one(deltaB);
	}

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

	// Bob gets encrypted input from alice to a decrypt comparison result
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
			toAlice.writeInt(answer);
			toAlice.flush();
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
		// MAYBE IF OVER FLOW HAPPENS?
		// Modified_Protocol3(z.mod(powL), z);	
	
		c = z.divide(BigInteger.valueOf(divisor));
		if(isDGK) {
			writeObject(DGKOperations.encrypt(c, dgk_public));	
		}
		else {
			writeObject(PaillierCipher.encrypt(c, paillier_public));
		}
		toAlice.flush();
		/*
		 *  Unlike Comparison, it is decided Bob shouldn't know the answer.
		 *  This is because Bob KNOWS d, and can decrypt [x/d]
		 *  
		 *  Since the idea is not leak the numbers themselves, 
		 *  it is decided Bob shouldn't receive [x/d]
		 */
	}
	
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