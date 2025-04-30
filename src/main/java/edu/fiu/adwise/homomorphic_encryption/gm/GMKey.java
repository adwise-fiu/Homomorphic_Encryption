package edu.fiu.adwise.homomorphic_encryption.gm;

import java.math.BigInteger;

/**
 * Interface representing a Goldwasser-Micali (GM) key.
 * This interface provides a method to retrieve the modulus \( n \),
 * which is a key parameter in the GM encryption scheme.
 */
public interface GMKey {
	/**
	 * Retrieves the modulus (n) associated with the GM key.
	 *
	 * @return The modulus (n) as a BigInteger.
	 */
	BigInteger getN();
}
