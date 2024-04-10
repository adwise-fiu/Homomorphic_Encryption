package test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

import security.misc.HomomorphicException;
import security.socialistmillionaire.bob;

import static org.junit.Assert.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class test_bob implements Runnable, constants
{
	private static final Logger logger = LogManager.getLogger(test_bob.class);
	private final  int port;
	private static ServerSocket bob_socket = null;
	private static Socket bob_client = null;
	private final bob andrew;
	private static final BigInteger [] mid = IntegrationTests.generate_mid();
	private final String bob_class_name;
	
	public test_bob(bob andrew, int port) {
		this.andrew = andrew;
		this.port = port;
		this.bob_class_name = andrew.getClass().getName();
	}
	
	// This could be in Bob's Main Method
	public void run() {
		try
		{
			bob_socket = new ServerSocket(this.port);
            logger.info("{} is ready...", bob_class_name);
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
			throw new RuntimeException(x);
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
				logger.error(e.getStackTrace());
			}
		}
	}

	public void test_outsourced_multiply(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
		// Test out-source multiplication, DGK
        logger.info("{}: Testing Multiplication, DGK Mode: {}", bob_class_name, dgk_mode);
		andrew.setDGKMode(dgk_mode);
		for(int i = 0; i < 3; i++) {
			andrew.multiplication();
		}
	}

	public void test_outsourced_division(boolean dgk_mode)
			throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("{}: Testing Division, DGK Mode: {}", bob_class_name, dgk_mode);
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
        logger.info("{}: Testing Protocol 1, DGK Mode:{}", bob_class_name, dgk_mode);
		andrew.setDGKMode(dgk_mode);
		boolean answer;
		for(BigInteger l: mid) {
			// X <= Y is true
			answer = andrew.Protocol1(l);
			assertTrue(answer);
		}
		for(BigInteger l: mid) {
			// X <= Y is true
			answer = andrew.Protocol1(l);
			assertTrue(answer);
		}
		for(BigInteger l: mid) {
			// X <= Y is false
			answer = andrew.Protocol1(l);
			assertFalse(answer);
		}
	}

	// This checks for X >= Y
	public void test_protocol_two(boolean dgk_mode)
			throws IOException, ClassNotFoundException, HomomorphicException {
        logger.info("{}: Testing Protocol 2, DGK Mode:{}", bob_class_name, dgk_mode);
		andrew.setDGKMode(dgk_mode);
		boolean answer;

		if (dgk_mode) {
			if (andrew.getClass() != security.socialistmillionaire.bob.class) {
				for (int i = 0; i < mid.length; i++) {
					// Original - Skipped
					// Veugen (X > Y) - false
					// Joye (X >= Y) - false
					answer = andrew.Protocol2();
					assertFalse(answer);

					// Original - Skipped
					// Veugen (X > Y) - false
					// Joye (X >= Y) - true
					answer = andrew.Protocol2();
					if (andrew.getClass() == security.socialistmillionaire.bob_joye.class) {
						assertTrue(answer);
					}
					else{
						assertFalse(answer);
					}

					// Original - Skipped
					// Veugen (X > Y) - true
					// Joye (X >= Y) - true
					answer = andrew.Protocol2();
					assertTrue(answer);
				}
			}
		}
		else {
			// X >= Y is false
			for(int i = 0; i < mid.length; i++) {
				// Original (X >= Y) - false
				// Veugen (X >= Y) - false
				// Joye (X >= Y) - false
				answer = andrew.Protocol2();
				assertFalse(answer);

				// Original (X >= Y) - true
				// Veugen (X >= Y) - true
				// Joye (X >= Y) - true
				answer = andrew.Protocol2();
				assertTrue(answer);

				// Original (X >= Y) - true
				// Veugen (X >= Y) - true
				// Joye (X >= Y) - true
				answer = andrew.Protocol2();
				assertTrue(answer);
			}
		}
	}

	public void test_sorting(boolean dgk_mode) throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("{}: Testing Sorting, DGK Mode:{}", bob_class_name, dgk_mode);
		andrew.setDGKMode(dgk_mode);
		if (dgk_mode) {
			if (andrew.getClass() == security.socialistmillionaire.bob.class) {
                logger.info("{}: Skipping Sorting because will crash with this alice version...", bob_class_name);
				return;
			}
			andrew.sort();
		}
		else {
			andrew.sort();
		}
	}

	public void test_private_equality(boolean dgk_mode) throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("{}: Testing Equality Check w/o encryption, DGK Mode:{}", bob_class_name, dgk_mode);
		andrew.setDGKMode(dgk_mode);
		andrew.Protocol1(FORTY_NINE);
		andrew.Protocol1(FIFTY);
		andrew.Protocol1(FIFTY_ONE);
	}

	public void test_encrypted_equality(boolean dgk_mode) throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("{}: Testing Equality Check, DGK Mode:{}", bob_class_name, dgk_mode);
		andrew.setDGKMode(dgk_mode);
		andrew.encrypted_equals();
		andrew.encrypted_equals();
		andrew.encrypted_equals();	
	}
}