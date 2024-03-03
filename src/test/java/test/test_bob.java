package test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

import security.misc.HomomorphicException;
import security.socialistmillionaire.bob;

import static org.junit.Assert.*;

public class test_bob implements Runnable, constants
{
	private final  int port;
	private static ServerSocket bob_socket = null;
	private static Socket bob_client = null;
	private final bob andrew;
	private static final BigInteger [] mid = IntegrationTests.generate_mid();
	
	public test_bob(bob andrew, int port) {
		this.andrew = andrew;
		this.port = port;
	}
	
	// This could be in Bob's Main Method
	public void run() {
		try
		{	
			bob_socket = new ServerSocket(this.port);
			System.out.println("Bob is ready...");
			bob_client = bob_socket.accept();
			andrew.set_socket(bob_client);
			andrew.sendPublicKeys();

			test_outsourced_multiply(true);
			test_outsourced_multiply(false);

			test_outsourced_division(true);
			test_outsourced_division(false);

			test_protocol_one(true);
			test_protocol_one(false);

			test_protocol_two(true);
			test_protocol_two(false);

			test_sorting(true);
			test_sorting(false);

			test_private_equality(true);
			test_private_equality(false);

			test_encrypted_equality(true);
			test_encrypted_equality(false);
		}
		catch (IOException | ClassNotFoundException | HomomorphicException | IllegalArgumentException x) {
			x.printStackTrace();
		}
		finally {
			try {
				if(bob_client != null) {
					bob_client.close();
				}
				if(bob_socket != null) {
					bob_socket.close();
				}
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public void test_outsourced_multiply(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
		// Test out-source multiplication, DGK
		System.out.println("Bob: Testing Multiplication, DGK Mode: " + dgk_mode);
		andrew.setDGKMode(dgk_mode);
		for(int i = 0; i < 3; i++) {
			andrew.multiplication();
		}
	}

	public void test_outsourced_division(boolean dgk_mode)
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

	public void test_protocol_one(boolean dgk_mode)
			throws IOException, ClassNotFoundException, HomomorphicException {
		System.out.println("Bob: Testing Protocol 1, DGK Mode:" + dgk_mode);
		andrew.setDGKMode(dgk_mode);
		boolean answer;
		for(BigInteger l: mid) {
			// X <= Y is true
			answer = andrew.Protocol1(l);
			//System.out.println(answer);
			assertTrue(answer);
		}
		for(BigInteger l: mid) {
			// X <= Y is true
			answer = andrew.Protocol1(l);
			//System.out.println(answer);
			assertTrue(answer);
		}
		for(BigInteger l: mid) {
			// X <= Y is false
			answer = andrew.Protocol1(l);
			//System.out.println(answer);
			assertFalse(answer);
		}
	}

	// This checks for X >= Y
	public void test_protocol_two(boolean dgk_mode)
			throws IOException, ClassNotFoundException, HomomorphicException {
		System.out.println("Bob: Testing Protocol 2, DGK Mode:" + dgk_mode);
		andrew.setDGKMode(dgk_mode);
		boolean answer;

		if (dgk_mode) {
			if (andrew.getClass() != security.socialistmillionaire.bob.class) {
				for (int i = 0; i < mid.length; i++) {
					// X > Y is false
					answer = andrew.Protocol2();
					assertFalse(answer);

					// X > Y is false
					answer = andrew.Protocol2();
					assertFalse(answer);

					// X > Y is true
					answer = andrew.Protocol2();
					assertTrue(answer);
				}
			}
		}
		else {
			// X >= Y is false
			for(int i = 0; i < mid.length; i++) {
				answer = andrew.Protocol2();
				//System.out.println(answer);
				assertFalse(answer);

				answer = andrew.Protocol2();
				//System.out.println(answer);
				assertTrue(answer);

				answer = andrew.Protocol2();
				//System.out.println(answer);
				assertTrue(answer);
			}
		}
	}

	public void test_sorting(boolean dgk_mode) throws HomomorphicException, IOException, ClassNotFoundException {
		System.out.println("Bob: Testing Sorting, DGK Mode:" + dgk_mode);
		andrew.setDGKMode(dgk_mode);
		if (dgk_mode) {
			if (andrew.getClass() == security.socialistmillionaire.bob.class) {
				System.out.println("Bob: Skipping Sorting because will crash with this alice version...");
				return;
			}
			andrew.sort();
		}
		else {
			andrew.sort();
		}
	}

	public void test_private_equality(boolean dgk_mode) throws HomomorphicException, IOException, ClassNotFoundException {
		System.out.println("Bob: Testing Equality Check w/o encryption, DGK Mode:" + dgk_mode);
		andrew.setDGKMode(dgk_mode);
		andrew.Protocol1(FOURTY_NINE);
		andrew.Protocol1(FIFTY);
		andrew.Protocol1(FIFTY_ONE);
	}

	public void test_encrypted_equality(boolean dgk_mode) throws HomomorphicException, IOException, ClassNotFoundException {
		System.out.println("Bob: Testing Equality Check, DGK Mode:" + dgk_mode);
		andrew.setDGKMode(dgk_mode);
		andrew.encrypted_equals();
		andrew.encrypted_equals();
		andrew.encrypted_equals();	
	}
}