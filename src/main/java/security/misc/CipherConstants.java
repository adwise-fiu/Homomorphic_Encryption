package security.misc;

import java.math.BigInteger;

// This interface collects constants used by a lot of
// 1- KeyPairGenerators
// 2- Ciphers (ElGamal)
public interface CipherConstants 
{
	// controls the error probability of the primality testing algorithm
    int CERTAINTY = 40;
	// This variable has been needed a lot, but I want to keep it a Java 8 library
	// So it can be used in Android apps with NO issues
    BigInteger TWO = new BigInteger("2");
	
	// Technically used only in ElGamal Private Key
    // Same as DGK: U with 16 bits
    BigInteger FIELD_SIZE = TWO.pow(16).nextProbablePrime();
	
	// Used in NTL for Jacobi
    BigInteger THREE = new BigInteger("3");
	BigInteger FOUR = new BigInteger("4");
	BigInteger FIVE = new BigInteger("5");

	BigInteger EIGHT = new BigInteger("8");

	// Misc
    BigInteger NEG_ONE = new BigInteger("-1");
	
	// For tracking time in nano-seconds to seconds
    int BILLION = BigInteger.TEN.pow(9).intValue();
}
