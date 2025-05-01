/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.homomorphic_encryption.misc;

/**
 * This class represents a custom exception for errors related to homomorphic encryption operations.
 * It extends the {@link Exception} class and provides a constructor to specify an error message.
 */
public class HomomorphicException extends Exception {
	private static final long serialVersionUID = 8999421918165322916L;

	/**
	 * Constructs a new {@code HomomorphicException} with the specified detail message.
	 *
	 * @param message The detail message describing the exception.
	 */
	public HomomorphicException(String message) {
		super(message);
	}
}
