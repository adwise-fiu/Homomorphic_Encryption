package edu.fiu.adwise.homomorphic_encryption.paillier;

import java.math.BigInteger;

public interface PaillierKey 
{
	BigInteger getN();
	BigInteger getModulus();
}
