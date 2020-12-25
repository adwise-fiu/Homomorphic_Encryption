package security.misc;

import java.math.BigInteger;

// This interface collects constants used by a lot of
// 1- KeyPairGenerators
// 2- Ciphers (ElGamal)
public interface CipherConstants 
{
	// controls the error probability of the primality testing algorithm
	final static int CERTAINTY = 40;
	// This variable has been needed a lot, but I want to keep it a Java 8 library
	// So it can be used in Android apps with NO issues
	final static BigInteger TWO = new BigInteger("2");
	
	// Technically used only in ElGamal Private Key
    // Same as DGK: U with 16 bits
	final static BigInteger FIELD_SIZE = TWO.pow(16).nextProbablePrime();
	
	// Used in NTL for Jacobi
	final static BigInteger THREE = new BigInteger("3");
	final static BigInteger FOUR = new BigInteger("4");
	final static BigInteger FIVE = new BigInteger("5");
	final static BigInteger SEVEN = new BigInteger("7");
	final static BigInteger EIGHT = new BigInteger("8");

	// Misc
	final static BigInteger NEG_ONE = new BigInteger("-1");
	
	// For tracking time in nano-seconds to seconds
	final int BILLION = BigInteger.TEN.pow(9).intValue();
}
