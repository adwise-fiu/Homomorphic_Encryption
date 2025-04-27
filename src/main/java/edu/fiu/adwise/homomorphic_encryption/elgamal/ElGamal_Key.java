package edu.fiu.adwise.homomorphic_encryption.elgamal;

import java.math.BigInteger;

public interface ElGamal_Key 
{
	BigInteger getP();
	void set_additive(boolean additive);
}
