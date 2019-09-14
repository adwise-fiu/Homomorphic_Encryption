package security.paillier;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

/*
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
*/

// Check
// package org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;

public final class PaillierPublicKey implements Serializable, PaillierKey, PublicKey
{
	private static final long serialVersionUID = -4009702553030484256L;

    //private static final AlgorithmIdentifier DEFAULT_ALGORITHM_IDENTIFIER = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
    //private transient AlgorithmIdentifier algorithmIdentifier;

	// k1 is the security parameter. It is the number of bits in n.
	public final int keysize;
	
	// n = pq is a product of two large primes (such N is known as RSA modulous)
    protected final BigInteger n;
    protected final BigInteger modulus;
    protected final BigInteger g;
    
    public PaillierPublicKey(int keysize, BigInteger n, BigInteger modulus, BigInteger g)
    {
        //this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
    	this.keysize = keysize;
    	this.n = n;
    	this.modulus = modulus;
        this.g = g;
    }
    
    private void readObject(ObjectInputStream aInputStream) throws ClassNotFoundException,
            IOException
    {
        aInputStream.defaultReadObject();
    }

    private void writeObject(ObjectOutputStream aOutputStream) throws IOException
    {
        aOutputStream.defaultWriteObject();
    }
    
    public String toString()
    {
    	String answer = "";
    	answer += "k1 = " + this.keysize + ", " + '\n';
    	answer += "n = " + this.n + ", " + '\n';
    	answer += "modulus = " + this.modulus + '\n';
    	answer += "g = " + this.g + '\n';
        return answer;
    }
    
    public BigInteger getN()
    {
    	return n;
    }
    
	public BigInteger getModulus() 
	{
		return modulus;
	}
	
	public String getAlgorithm() 
	{
		return "Paillier";
	}

	public String getFormat() 
	{
		return "X.509";
	}

	public byte[] getEncoded() 
	{
		return null;
        //return KeyUtil.getEncodedSubjectPublicKeyInfo(algorithmIdentifier, new RSAPublicKey(getModulus(), getPublicExponent()));
	}
}