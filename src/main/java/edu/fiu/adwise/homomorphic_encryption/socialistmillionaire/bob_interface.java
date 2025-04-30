/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.socialistmillionaire;

import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;

public interface bob_interface {

    void encrypted_equals() throws IOException, HomomorphicException, ClassNotFoundException;

    // Used to compare alice's private integer x and Bob's private integer y
    boolean Protocol1(BigInteger y)
            throws IOException, IllegalArgumentException, HomomorphicException, ClassNotFoundException;

    // Used to compare alice's encrypted x and y, bob will return if [[X >= Y]]
    boolean Protocol2()
            throws IOException, ClassNotFoundException, HomomorphicException;

    void division(long divisor) throws IOException, ClassNotFoundException, HomomorphicException;

    void multiplication()
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException;

    void sort() throws IOException, ClassNotFoundException, HomomorphicException;

    void sendPublicKeys() throws IOException;

    void set_socket(Socket socket) throws IOException;
}