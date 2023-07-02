package security.socialistmillionaire;

import security.misc.HomomorphicException;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.util.List;

public interface alice_interface {

    // Used to compare alice's private integer x and bob's private integer y
    boolean Protocol1(BigInteger x)
            throws IOException, IllegalArgumentException, HomomorphicException, ClassNotFoundException;

    // Used to compare alice's encrypted x and y, bob will return if [[X >= Y]]
    boolean Protocol2(BigInteger x, BigInteger y)
            throws IOException, ClassNotFoundException, HomomorphicException;

    BigInteger division(BigInteger x, long d) throws IOException, ClassNotFoundException, HomomorphicException;
    BigInteger multiplication(BigInteger x, BigInteger y)
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException;

    void receivePublicKeys() throws IOException, ClassNotFoundException;

    BigInteger[] getKValues(BigInteger [] input, int k, boolean biggest_first)
            throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException;

    BigInteger[] getKValues(List<BigInteger> input, int k, boolean smallest_first)
            throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException;

    void set_socket(Socket socket) throws IOException;
}
