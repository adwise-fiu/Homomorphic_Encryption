package test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;

import security.misc.HomomorphicException;
import security.socialistmillionaire.bob;

import static org.junit.Assert.*;

public class test_bob implements Runnable
{
	private final  int port;
	// Initialize Alice and Bob
	private static ServerSocket bob_socket = null;
	private static Socket bob_client = null;
	private static bob andrew = null;

	private static final BigInteger [] mid = IntegrationTests.generate_mid();
	
	private final KeyPair p;
	private final KeyPair d;
	private final KeyPair e;
	
	public test_bob(KeyPair paillier, KeyPair dgk, KeyPair elgamal, int port) {
		this.p = paillier;
		this.d = dgk;
		this.e = elgamal;
		this.port = port;
	}
	
	// This could be in Bob's Main Method
	public void run() {
		try
		{	
			bob_socket = new ServerSocket(this.port);
			System.out.println("Bob is ready...");
			bob_client = bob_socket.accept();
			andrew = new bob(bob_client, this.p, this.d, this.e);
			andrew.sendPublicKeys();


			test_outsourced_multiply(true);
			test_outsourced_multiply(false);

			test_outsourced_division(true);
			test_outsourced_division(false);

			test_protocol_one(true);
			test_protocol_one(false);

			test_sorting(true);
			test_sorting(false);

			test_protocol_two(true);
			test_protocol_two(false);



		}
		catch (IOException | ClassNotFoundException | HomomorphicException | IllegalArgumentException x) {
			x.printStackTrace();
		}
		finally
		{
			try 
			{
				if(bob_client != null) {
					bob_client.close();
				}
				if(bob_socket != null) {
					bob_socket.close();
				}
			}
			catch (IOException e) 
			{
				e.printStackTrace();
			}
		}
	}

	public static void test_outsourced_multiply(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
		// Test out-source multiplication, DGK
		System.out.println("Bob: Testing Multiplication, DGK Mode: " + dgk_mode);
		andrew.setDGKMode(dgk_mode);
		for(int i = 0; i < 3; i++) {
			andrew.multiplication();
		}
	}

	public static void test_outsourced_division(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
		System.out.println("Bob: Testing Division, DGK Mode: " + dgk_mode);
		// Division Protocol Test, Paillier
		andrew.setDGKMode(dgk_mode);
		andrew.division(2);
		andrew.division(3);
		andrew.division(4);
		andrew.division(5);
		andrew.division(25);
	}

	public static void test_protocol_one(boolean dgk_mode)
			throws IOException, ClassNotFoundException, HomomorphicException {
		System.out.println("Bob: Testing Protocol 1, DGK Mode:" + dgk_mode);
		andrew.setDGKMode(dgk_mode);
		boolean answer;
		for(int i = 0; i < 16 * 2; i++) {
			// X <= Y is true
			answer = andrew.Protocol1(mid[i % 16]);
			assertTrue(answer);
		}
		for(int i = 0; i < 16; i++) {
			// X <= Y is false
			answer = andrew.Protocol1(mid[i % 16]);
			assertFalse(answer);
		}
	}

	// This checks for X >= Y
	public static void test_protocol_two(boolean dgk_mode)
			throws IOException, ClassNotFoundException, HomomorphicException {
		System.out.println("Bob: Testing Protocol 2, DGK Mode:" + dgk_mode);
		andrew.setDGKMode(dgk_mode);

		if (dgk_mode) {
			if (andrew.getClass() == security.socialistmillionaire.bob.class) {
				// Protocol 2 won't work on regular alice
				return;
			}
		}

		boolean answer;
		// X >= Y is false
		for(int i = 0; i < 16; i++) {
			answer = andrew.Protocol2();
			assertFalse(answer);
		}

		// X >= Y is true
		for(int i = 0; i < 16; i++) {
			answer = andrew.Protocol2();
			assertTrue(answer);
		}
	}

	public static void test_sorting(boolean dgk_mode) {
		System.out.println("Bob: Testing Sorting, DGK Mode:" + dgk_mode);
		andrew.setDGKMode(dgk_mode);
		if (dgk_mode) {
			if (andrew.getClass() == security.socialistmillionaire.bob.class) {
				// Protocol 2 won't work on regular alice
				return;
			}
		}
		andrew.run();
	}
}