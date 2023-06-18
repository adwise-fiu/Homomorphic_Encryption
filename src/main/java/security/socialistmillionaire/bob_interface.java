package security.socialistmillionaire;

import security.misc.HomomorphicException;

import java.io.IOException;
import java.math.BigInteger;

public interface bob_interface {

    // Used to compare alice's private integer x and Bob's private integer y
    boolean Protocol1(BigInteger y)
            throws IOException, IllegalArgumentException, HomomorphicException, ClassNotFoundException;

    // Used to compare alice's encrypted x and y, bob will return if [[X >= Y]]
    boolean Protocol2()
            throws IOException, ClassNotFoundException, HomomorphicException;

    void division(long divisor) throws IOException, ClassNotFoundException, HomomorphicException;

    void multiplication()
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException;

}