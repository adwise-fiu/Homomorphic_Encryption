package security.paillier;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

// Links:
// https://github.com/AndrewQuijano/bc-java/blob/master/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/
	
//org/bouncycastle/jcajce/provider/asymmetric/
/*
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
*/

//Check
//package org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;

//public final class PaillierPrivateKey extends ASN1Object implements Serializable, PaillierKey, PrivateKey, PKCS12BagAttributeCarrier
public final class PaillierPrivateKey implements Serializable, PaillierKey, PrivateKey
{
	//private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();
	private static final long serialVersionUID = -3342551807566493368L;

	// k1 is the security parameter. It is the number of bits in n.
	private final int key_size;

	protected final BigInteger n;
	protected final BigInteger modulus;
	protected final BigInteger g;

	protected final BigInteger lambda;
	protected final BigInteger mu;
	
	protected final BigInteger rho;
	protected final BigInteger alpha;
	
	public PaillierPrivateKey(int key_size, BigInteger n, BigInteger mod, 
			BigInteger lambda, BigInteger mu, BigInteger g, BigInteger alpha)
	{
		this.key_size = key_size;
		this.n = n;
		this.modulus = mod;
		this.lambda = lambda;
		this.mu = mu;
		this.g = g;
		this.alpha = alpha;
		this.rho = PaillierCipher.L(this.g.modPow(this.lambda, this.modulus), this.n).modInverse(this.modulus);
	}

	private void readObject(ObjectInputStream aInputStream) 
			throws ClassNotFoundException, IOException
	{
		aInputStream.defaultReadObject();
	}

	private void writeObject(ObjectOutputStream aOutputStream) throws IOException
	{
		aOutputStream.defaultWriteObject();
	}

	public boolean equals(Object o)
	{
		if (!(o instanceof PaillierPrivateKey))
		{
			return false;
		}

		if (o == this)
		{
			return true;
		}
		PaillierPrivateKey key = (PaillierPrivateKey) o;
		return n.equals(key.n) && modulus.equals(key.modulus) 
				&& lambda.equals(key.lambda) && mu.equals(key.mu);
	}

	// Omitting secret key parameters
	public String toString()
	{
		String answer = "";
		answer += "key_size = " + this.key_size + ", " + '\n';
		answer += "n =        " + this.n + ", " + '\n';
		answer += "modulus =  " + this.modulus + '\n';
		answer += "g =        " + this.g + '\n';
		//answer += "lambda =   " + lambda + '\n';
		//answer += "alpha =    " + this.alpha+ '\n';
		//answer += "mu =       " + mu;
		return answer;
	}

	public int get_Keysize() 
	{
		return key_size;
	}

	public BigInteger getModulus() 
	{
		return modulus;
	}
	
    public BigInteger getN()
    {
    	return n;
    }

	public String getAlgorithm() 
	{
		return "Paillier";
	}

	public String getFormat() 
	{
		return "PKCS#8";
	}
	
	public byte[] getEncoded() 
	{
		return null;
		/*
		return KeyUtil.getEncodedPrivateKeyInfo(
				new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, 
						DERNull.INSTANCE), this);
		*/
	}
	
	/*
	public ASN1Encodable getBagAttribute(ASN1ObjectIdentifier oid)
	{
		return attrCarrier.getBagAttribute(oid);
	}

	public Enumeration<?> getBagAttributeKeys()
	{
		return attrCarrier.getBagAttributeKeys();
	}

	public void setBagAttribute(ASN1ObjectIdentifier oid, ASN1Encodable attribute)
	{
		attrCarrier.setBagAttribute(oid, attribute);
	}

	public PaillierPrivateKey(ASN1Sequence seq)
	{
		@SuppressWarnings("unchecked")
		Enumeration<ASN1Integer> e = seq.getObjects();
		n = e.nextElement().getValue();
		modulus = e.nextElement().getValue();
		lambda = e.nextElement().getValue();
		mu = e.nextElement().getValue();
		g = e.nextElement().getValue();
		key_size = e.nextElement().getValue().intValue();
		this.alpha = e.nextElement().getValue();
		this.rho = PaillierCipher.L(this.g.modPow(this.lambda, this.modulus), this.n);
        if (e.hasMoreElements())
        {
            e.nextElement();
        }
	}
	
	public ASN1Primitive toASN1Primitive() 
	{
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new ASN1Integer(n));
		v.add(new ASN1Integer(modulus));
		v.add(new ASN1Integer(lambda));
		v.add(new ASN1Integer(mu));
		v.add(new ASN1Integer(BigInteger.valueOf(key_size)));
		return new DERSequence(v);
	}
	*/
}