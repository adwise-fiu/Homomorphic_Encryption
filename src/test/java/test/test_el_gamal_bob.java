package test;

import security.misc.HomomorphicException;
import security.socialistmillionaire.bob_veugen;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class test_el_gamal_bob implements Runnable {
    private static ServerSocket bob_socket = null;
    private static Socket bob_client = null;
    private final bob_veugen andrew;
    private final int port;

    public test_el_gamal_bob(bob_veugen andrew, int port) {
        this.andrew = andrew;
        this.port = port;
    }

    // This would be in Bob's Main Method
    public void run() {
        try
        {
            bob_socket = new ServerSocket(port);
            System.out.println("Bob is ready...");
            bob_client = bob_socket.accept();
            andrew.sendPublicKeys();

            test_sorting();
            test_protocol_two();
            test_outsourced_multiply();
            test_outsourced_divide();
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

    public void test_sorting() throws IOException, ClassNotFoundException, HomomorphicException {
        if(andrew.getElGamalPublicKey().ADDITIVE) {
            andrew.repeat_ElGamal_Protocol4();
        }
    }

    public void test_protocol_two() throws IOException, ClassNotFoundException, HomomorphicException {
        for(int i = 0; i < 16 * 3; i++) {
            andrew.ElGamal_Protocol4();
        }
    }

    public void test_outsourced_multiply() throws IOException, ClassNotFoundException {
        for(int i = 0; i < 3; i++) {
            andrew.ElGamal_multiplication();
        }
    }

    public void test_outsourced_divide() throws IOException, ClassNotFoundException, HomomorphicException {
        andrew.ElGamal_division(2);
        andrew.ElGamal_division(3);
        andrew.ElGamal_division(4);
        andrew.ElGamal_division(5);
        andrew.ElGamal_division(25);
    }

    public void test_addition() throws ClassNotFoundException, IOException
    {
        if(!andrew.getElGamalPublicKey().ADDITIVE) {
            andrew.addition(true);
            andrew.addition(true);
            andrew.addition(true);
        }
    }

    public void test_subtraction() throws IOException, ClassNotFoundException {
        if(!andrew.getElGamalPublicKey().ADDITIVE)
        {
            andrew.addition(false);
            andrew.addition(false);
            andrew.addition(false);
        }
    }
}
