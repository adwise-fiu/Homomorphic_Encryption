/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.socialistmillionaire;

import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.util.List;

/**
 * Interface defining the operations for Alice in the Socialist Millionaires' Problem (SMP) protocol.
 * This interface includes methods for secure multi-party computation using homomorphic encryption.
 */
public interface alice_interface {

    /**
     * Compares two encrypted integers for equality.
     *
     * @param x the first encrypted integer.
     * @param y the second encrypted integer.
     * @return true if the integers are equal, false otherwise.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     * @throws IOException if an I/O error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     */
    boolean encrypted_equals(BigInteger x, BigInteger y) throws HomomorphicException, IOException, ClassNotFoundException;

    /**
     * Compares Alice's private integer with Bob's private integer.
     *
     * @param x Alice's private integer.
     * @return true if the comparison satisfies the protocol, false otherwise.
     * @throws IOException if an I/O error occurs.
     * @throws IllegalArgumentException if an invalid argument is provided.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     */
    boolean Protocol1(BigInteger x)
            throws IOException, IllegalArgumentException, HomomorphicException, ClassNotFoundException;

    /**
     * Compares two encrypted integers and determines if the first is greater than or equal to the second.
     *
     * @param x the first encrypted integer.
     * @param y the second encrypted integer.
     * @return true if x is greater than or equal to y, false otherwise.
     * @throws IOException if an I/O error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     */
    boolean Protocol2(BigInteger x, BigInteger y)
            throws IOException, ClassNotFoundException, HomomorphicException;

    /**
     * Performs division on an encrypted integer.
     *
     * @param x the encrypted integer to divide.
     * @param d the divisor.
     * @return the result of the division as an encrypted integer.
     * @throws IOException if an I/O error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     */
    BigInteger division(BigInteger x, long d) throws IOException, ClassNotFoundException, HomomorphicException;

    /**
     * Performs multiplication on two encrypted integers.
     *
     * @param x the first encrypted integer.
     * @param y the second encrypted integer.
     * @return the result of the multiplication as an encrypted integer.
     * @throws IOException if an I/O error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     * @throws IllegalArgumentException if an invalid argument is provided.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     */
    BigInteger multiplication(BigInteger x, BigInteger y)
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException;

    /**
     * Receives public keys from the other party.
     *
     * @throws IOException if an I/O error occurs.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     */
    void receivePublicKeys() throws IOException, ClassNotFoundException;

    /**
     * Retrieves the k largest or smallest values from an array of encrypted integers.
     *
     * @param input the array of encrypted integers.
     * @param k the number of values to retrieve.
     * @param biggest_first true to retrieve the largest values, false to retrieve the smallest values.
     * @return an array of the k largest or smallest encrypted integers.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     * @throws IOException if an I/O error occurs.
     * @throws IllegalArgumentException if an invalid argument is provided.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     */
    BigInteger[] getKValues(BigInteger [] input, int k, boolean biggest_first)
            throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException;


    /**
     * Retrieves the k largest or smallest values from a list of encrypted integers.
     *
     * @param input the list of encrypted integers.
     * @param k the number of values to retrieve.
     * @param smallest_first true to retrieve the smallest values, false to retrieve the largest values.
     * @return an array of the k largest or smallest encrypted integers.
     * @throws ClassNotFoundException if the class of a serialized object cannot be found.
     * @throws IOException if an I/O error occurs.
     * @throws IllegalArgumentException if an invalid argument is provided.
     * @throws HomomorphicException if a homomorphic encryption error occurs.
     */
    BigInteger[] getKValues(List<BigInteger> input, int k, boolean smallest_first)
            throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException;

    /**
     * Sets the socket for communication.
     *
     * @param socket the socket to use for communication.
     * @throws IOException if an I/O error occurs.
     */
    void set_socket(Socket socket) throws IOException;
}
