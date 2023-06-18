package security.socialistmillionaire;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;

import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import security.dgk.DGKOperations;
import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamal_Ciphertext;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;
import security.paillier.PaillierPrivateKey;

public class bob extends socialist_millionaires implements Runnable, bob_interface
{
	/**
	 * Create a bob instance for running extending protocols such as comparing 
	 * encrypted numbers
	 * @throws IllegalArgumentException
	 * If a is not a Paillier Keypair or b is not a DGK key pair or c is not ElGamal Keypair
	 */
	public bob (Socket clientSocket,
			KeyPair a, KeyPair b, KeyPair c) 
					throws IOException, IllegalArgumentException
	{
		if(clientSocket != null) {
			this.toAlice = new ObjectOutputStream(clientSocket.getOutputStream());
			this.fromAlice = new ValidatingObjectInputStream(clientSocket.getInputStream());
			this.fromAlice.accept(
					java.math.BigInteger.class,
					java.lang.Number.class,
					java.util.HashMap.class,
					java.lang.Long.class,
					security.elgamal.ElGamal_Ciphertext.class
			);
			this.fromAlice.accept("[B");
			this.fromAlice.accept("[L*");
		}
		else {
			throw new NullPointerException("Client Socket is null!");
		}
		
		if (a.getPublic() instanceof PaillierPublicKey) {
			this.paillier_public = (PaillierPublicKey) a.getPublic();
			this.paillier_private = (PaillierPrivateKey) a.getPrivate();
			if(b.getPublic() instanceof DGKPublicKey) {
				this.dgk_public = (DGKPublicKey) b.getPublic();
				this.dgk_private = (DGKPrivateKey) b.getPrivate();
			}
			else {
				throw new IllegalArgumentException("Obtained Paillier Key Pair, Not DGK Key pair!");
			}
		}
		else if (a.getPublic() instanceof DGKPublicKey) {
			this.dgk_public = (DGKPublicKey) a.getPublic();
			this.dgk_private = (DGKPrivateKey) a.getPrivate();
			if (b.getPublic() instanceof PaillierPublicKey) {
				this.paillier_public = (PaillierPublicKey) a.getPublic();
				this.paillier_private = (PaillierPrivateKey) a.getPrivate();
			}
			else {
				throw new IllegalArgumentException("Obtained DGK Key Pair, Not Paillier Key pair!");
			}
		}
		
		if(c != null) {
			if (c.getPublic() instanceof ElGamalPublicKey) {
				this.el_gamal_public = (ElGamalPublicKey) c.getPublic();
				this.el_gamal_private= (ElGamalPrivateKey) c.getPrivate();
			}
			else {
				throw new IllegalArgumentException("Third Keypair MUST BE AN EL GAMAL KEY PAIR!");
			}
		}

		this.isDGK = false;
		powL = TWO.pow(dgk_public.getL());
	}
	
	/**
	 * if Alice wants to sort a list of encrypted numbers, use this method if you 
	 * will consistently sort using Protocol 2
	 */
	private void repeat_Protocol2()
			throws IOException, ClassNotFoundException, HomomorphicException {
		long start_time = System.nanoTime();
		int counter = 0;
		while(fromAlice.readBoolean()) {
			++counter;
			this.Protocol2();
		}
		System.out.println("Protocol 2 was used " + counter + " times!");
		System.out.println("Protocol 2 completed in " + (System.nanoTime() - start_time)/BILLION + " seconds!");
	}

	/**
	 * Please review "Improving the DGK comparison protocol" - Protocol 1
	 *
	 * @param y - plaintext value
	 * @return boolean
	 * @throws IllegalArgumentException - if y has more bits than is supported by provided DGK keys
	 */
	public boolean Protocol1(BigInteger y)
			throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {
		// Constraint...
		if(y.bitLength() > dgk_public.getL()) {
			throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, y is: " + y.bitLength() + " bits");
		}

		Object in;
		int deltaB = 0;
		BigInteger [] C;

		//Step 1: Bob sends encrypted bits to Alice
		BigInteger [] EncY = new BigInteger[y.bitLength()];
		for (int i = 0; i < y.bitLength(); i++) {
			EncY[i] = DGKOperations.encrypt(NTL.bit(y, i), dgk_public);
		}
		toAlice.writeObject(EncY);
		toAlice.flush();
		
		// Step 2: Alice...
		// Step 3: Alice...
		// Step 4: Alice...
		// Step 5: Alice...
		// Step 6: Check if one of the numbers in C_i is decrypted to 0.
		in = fromAlice.readObject();
		if(in instanceof BigInteger[]) {
			C = (BigInteger []) in;
		}
		else if (in instanceof BigInteger) {
			return false;
		}
		else {
			throw new IllegalArgumentException("Protocol 1, Step 6: Invalid object: " + in.getClass().getName());
		}

		for (BigInteger C_i: C) {
			if (DGKOperations.decrypt(C_i, dgk_private) == 0) {
				deltaB = 1;
				break;
			}
		}

		// Step 7: UNOFFICIAL
		// Inform Alice what deltaB is
		toAlice.writeInt(deltaB);
		toAlice.flush();

		// Step 8: UNOFFICIAL
		// Alice sends the answer, decrypt it and keep it for yourself
		// This is best used in situations like an auction where Bob needs to know
		in = fromAlice.readObject();
		if (in instanceof BigInteger) {
			return DGKOperations.decrypt((BigInteger) in, dgk_private) == 1;
		}
		else {
			throw new IllegalArgumentException("Invalid response from Alice in Step 8: " + in.getClass().getName());
		}
	}
	
	/**
	 * Please review "Improving the DGK comparison protocol" - Protocol 1
	 * NOTE: The paper has a typo!
	 * This protocol computes X >= Y NOT X <= Y
	 */
	
	public boolean Protocol2()
			throws ClassNotFoundException, IOException, HomomorphicException {
		// Step 1: Receive z from Alice
		// Get the input and output streams
		int answer;
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
		toAlice.writeObject(PaillierCipher.encrypt(z.divide(powL), paillier_public));
		toAlice.flush();
		
		// Step 6 - 7: Alice Computes [[x <= y]]
		
		// Step 8 (UNOFFICIAL): Alice needs the answer for [[x <= y]]
		x = fromAlice.readObject();
		if (x instanceof BigInteger) {
			answer = PaillierCipher.decrypt((BigInteger) x, paillier_private).intValue();
			toAlice.writeInt(answer);
			toAlice.flush();
			return answer == 1;
		}
		else {
			throw new IllegalArgumentException("Invalid response from Alice in Step 8! " + x.getClass().getName());
		}
	}

	// Support addition and subtraction
	public void addition(boolean addition) 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in;
		ElGamal_Ciphertext enc_x_prime;
		ElGamal_Ciphertext enc_y_prime;
		BigInteger x_prime;
		BigInteger y_prime;
		
		// Step 2
		in = fromAlice.readObject();
		if(in instanceof ElGamal_Ciphertext) {
			enc_x_prime = (ElGamal_Ciphertext) in;
		}
		else {
			throw new IllegalArgumentException("Didn't get [[x']] from Alice: " + in.getClass().getName());
		}
		
		in = fromAlice.readObject();
		if(in instanceof ElGamal_Ciphertext) {
			enc_y_prime = (ElGamal_Ciphertext) in;
		}
		else {
			throw new IllegalArgumentException("Didn't get [[y']] from Alice: " + in.getClass().getName());		
		}
		
		// Step 3
		x_prime = ElGamalCipher.decrypt(enc_x_prime, el_gamal_private);
		y_prime = ElGamalCipher.decrypt(enc_y_prime, el_gamal_private);
		if(addition) {
			toAlice.writeObject(ElGamalCipher.encrypt(x_prime.add(y_prime), el_gamal_public));	
		}
		else {
			toAlice.writeObject(ElGamalCipher.encrypt(x_prime.subtract(y_prime), el_gamal_public));
		}
		toAlice.flush();
	}

	public void ElGamal_division(long divisor)
			throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException {
		BigInteger c;
		BigInteger z;
		ElGamal_Ciphertext enc_z;
		Object alice = fromAlice.readObject();
		if(alice instanceof ElGamal_Ciphertext) {
			enc_z = (ElGamal_Ciphertext) alice;
		}
		else {
			throw new IllegalArgumentException("Division: No ElGamal Ciphertext found! " + alice.getClass().getName());
		}
	
		z = ElGamalCipher.decrypt(enc_z, el_gamal_private);
		if(!FAST_DIVIDE) {
			Protocol1(z.mod(BigInteger.valueOf(divisor)));
		}
		
		c = z.divide(BigInteger.valueOf(divisor));
		toAlice.writeObject(ElGamalCipher.encrypt(c, el_gamal_public));
		toAlice.flush();
		/*
		 *  Unlike Comparison, it is decided Bob shouldn't know the answer.
		 *  This is because Bob KNOWS d, and can decrypt [x/d]
		 *  
		 *  Since the idea is not leak the numbers themselves, 
		 *  it is decided Bob shouldn't receive [x/d]
		 */
	}
	
	public void ElGamal_multiplication() 
			throws IOException, ClassNotFoundException, IllegalArgumentException
	{
		Object in;
		ElGamal_Ciphertext enc_x_prime;
		ElGamal_Ciphertext enc_y_prime;
		BigInteger x_prime;
		BigInteger y_prime;
		
		// Step 2
		in = fromAlice.readObject();
		if(in instanceof ElGamal_Ciphertext) {
			enc_x_prime = (ElGamal_Ciphertext) in;
		}
		else {
			throw new IllegalArgumentException("Didn't get [[x']] from Alice: " + in.getClass().getName());
		}
		
		in = fromAlice.readObject();
		if(in instanceof ElGamal_Ciphertext) {
			enc_y_prime = (ElGamal_Ciphertext) in;
		}
		else {
			throw new IllegalArgumentException("Didn't get [[y']] from Alice: " + in.getClass().getName());		
		}
		
		// Step 3
		x_prime = ElGamalCipher.decrypt(enc_x_prime, el_gamal_private);
		y_prime = ElGamalCipher.decrypt(enc_y_prime, el_gamal_private);
		toAlice.writeObject(ElGamalCipher.encrypt(x_prime.multiply(y_prime), el_gamal_public));
		toAlice.flush();
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
			toAlice.writeObject(DGKOperations.encrypt(x_prime.multiply(y_prime).mod(dgk_public.getU()), dgk_public));
		}
		else {
			x_prime = PaillierCipher.decrypt(x_prime, paillier_private);
			y_prime = PaillierCipher.decrypt(y_prime, paillier_private);
			// To avoid myself throwing errors of encryption must be [0, N), mod it now!
			toAlice.writeObject(PaillierCipher.encrypt(x_prime.multiply(y_prime).mod(paillier_public.getN()), paillier_public));
		}
		toAlice.flush();
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
			toAlice.writeObject(DGKOperations.encrypt(c, dgk_public));	
		}
		else {
			toAlice.writeObject(PaillierCipher.encrypt(c, paillier_public));
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
			toAlice.writeObject(dgk_public);
			System.out.println("Bob sent DGK Public Key to Alice");
		}
		else {
			toAlice.writeObject(BigInteger.ZERO);
		}
		if(paillier_public != null) {
			toAlice.writeObject(paillier_public);
			System.out.println("Bob sent Paillier Public Key to Alice");
		}
		else {
			toAlice.writeObject(BigInteger.ZERO);
		}
		if(el_gamal_public != null) {
			toAlice.writeObject(el_gamal_public);
			System.out.println("Bob sent ElGamal Public Key to Alice");
		}
		else {
			toAlice.writeObject(BigInteger.ZERO);
		}
		toAlice.flush();
	}
	
	public void run() 
	{
		try {
			repeat_Protocol2();
		}
		catch (ClassNotFoundException | IOException | IllegalArgumentException | HomomorphicException e) {
			e.printStackTrace();
		}
	}
}