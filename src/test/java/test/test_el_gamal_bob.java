/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package test;

import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.socialistmillionaire.bob_elgamal;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class test_el_gamal_bob extends test_bob implements Runnable {
    private static final Logger logger = LogManager.getLogger(test_el_gamal_bob.class);
    private static ServerSocket bob_socket = null;
    private static Socket bob_client = null;
    private final bob_elgamal andrew;
    private final int port;

    public test_el_gamal_bob(bob_elgamal andrew, int port) {
        super(andrew, port);
        this.andrew = andrew;
        this.port = port;
    }

    // This would be in Bob's Main Method
    public void run() {
        try
        {
            bob_socket = new ServerSocket(port);
            logger.info("Bob is ready...");
            bob_client = bob_socket.accept();
            andrew.set_socket(bob_client);
            andrew.sendPublicKeys();

            test_sorting(false);
            test_protocol_two(false);
            test_outsourced_multiply(false);
            test_outsourced_division(false);

            //andrew.set_el_gamal_additive(false);
            //test_addition();
            //test_subtraction();
        }
        catch (IOException | ClassNotFoundException | HomomorphicException | IllegalArgumentException x) {
            throw new RuntimeException(x);
        }
        finally
        {
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

    public void test_addition() throws ClassNotFoundException, IOException, HomomorphicException {
        if(!andrew.getElGamalPublicKey().additive) {
            andrew.addition(true);
            andrew.addition(true);
            andrew.addition(true);
        }
    }

    public void test_subtraction() throws IOException, ClassNotFoundException, HomomorphicException {
        if(!andrew.getElGamalPublicKey().additive) {
            andrew.addition(false);
            andrew.addition(false);
            andrew.addition(false);
        }
    }
}
