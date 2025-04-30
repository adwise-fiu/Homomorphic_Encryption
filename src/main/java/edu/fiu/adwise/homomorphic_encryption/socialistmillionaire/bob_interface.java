/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.socialistmillionaire;

import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;

/**
 * Interface defining the operations for Bob in the Socialist Millionaires' Problem (SMP) protocol.
 * This interface includes methods for secure multi-party computation using homomorphic encryption.
 */
public interface bob_interface {

    /**
     * Compares two encrypted integers for equality.
     *
     * @throws IOException if an I/O error occurs.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     */
    void encrypted_equals() throws IOException, HomomorphicException, ClassNotFoundException;

    /**
     * Compares Alice's private integer with Bob's private integer. This means this input is NOT encrypted!!
     *
     * @param y Bob's private integer.
     * @return true if the comparison satisfies the protocol, false otherwise.
     * @throws IOException if an I/O error occurs.
     * @throws IllegalArgumentException if an invalid argument is provided.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     */
    boolean Protocol1(BigInteger y) throws IOException, IllegalArgumentException, HomomorphicException, ClassNotFoundException;

    /**
     * Compares two encrypted integers and determines if the first is greater than or equal to the second.
     *
     * @return true if the first encrypted integer is greater than or equal to the second, false otherwise.
     * @throws IOException if an I/O error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     */
    boolean Protocol2() throws IOException, ClassNotFoundException, HomomorphicException;

    /**
     * Performs division on an encrypted integer with alice.
     *
     * @param divisor the divisor.
     * @throws IOException if an I/O error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     */
    void division(long divisor) throws IOException, ClassNotFoundException, HomomorphicException;

    /**
     * Performs multiplication on encrypted integers with alice.
     *
     * @throws IOException if an I/O error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     * @throws IllegalArgumentException if an invalid argument is provided.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     */
    void multiplication() throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException;

    /**
     * Sorts a collection of encrypted integers.
     *
     * @throws IOException if an I/O error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     */
    void sort() throws IOException, ClassNotFoundException, HomomorphicException;

    /**
     * Sends public keys to alice.
     *
     * @throws IOException if an I/O error occurs.
     */
    void sendPublicKeys() throws IOException;

    /**
     * Sets the socket for communication.
     *
     * @param socket the socket to use for communication.
     * @throws IOException if an I/O error occurs.
     */
    void set_socket(Socket socket) throws IOException;
}