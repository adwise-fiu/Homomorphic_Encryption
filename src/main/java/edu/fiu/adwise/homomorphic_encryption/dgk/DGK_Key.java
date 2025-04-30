package edu.fiu.adwise.homomorphic_encryption.dgk;

import java.math.BigInteger;

/**
 * Interface representing a DGK (Damgård-Geisler-Krøigaard) key.
 */
public interface DGK_Key
{
	/**
	 * Retrieves the value of \( u \), a parameter associated with the DGK key.
	 *
	 * @return the value of \( u \)
	 */
	BigInteger getU();

	/**
	 * Retrieves the modulus \( n \) associated with the DGK key.
	 *
	 * @return the modulus \( n \)
	 */
	BigInteger getN();

	/**
	 * Retrieves the bit length \( l \) of the DGK key.
	 *
	 * @return the bit length \( l \)
	 */
	int getL();
}
