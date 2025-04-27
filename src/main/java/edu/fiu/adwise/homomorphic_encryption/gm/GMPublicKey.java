package edu.fiu.adwise.homomorphic_encryption.gm;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public class GMPublicKey implements Serializable, PublicKey, GMKey
{
	@Serial
	private static final long serialVersionUID = -235857914395127699L;
	protected final BigInteger n;
	protected final BigInteger y;
	
	protected GMPublicKey(BigInteger n, BigInteger y) {
		this.n = n;
		this.y = y;
	}

	public String getAlgorithm() {
		return "Goldwasser-Micali";
	}

	public String getFormat() {
		return "X.509";
	}

	public byte[] getEncoded() {
		return null;
	}

	public BigInteger getN() {
		return this.n;
	}
}
