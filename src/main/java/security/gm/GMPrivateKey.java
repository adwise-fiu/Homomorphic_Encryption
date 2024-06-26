package security.gm;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;

public class GMPrivateKey implements Serializable, PrivateKey, GMKey
{
	@Serial
	private static final long serialVersionUID = -6003066379615503599L;
	protected final BigInteger p;
	protected final BigInteger q;
	protected final BigInteger n;
	
	protected GMPrivateKey(BigInteger p, BigInteger q) {
		this.p = p;
		this.q = q;
		this.n = p.multiply(q);
	}
	
	public String getAlgorithm() {
		return "Goldwasser-Micali";
	}

	public String getFormat() {
		return "PKCS#8";
	}

	public byte[] getEncoded() {
		return null;
	}
	
	public BigInteger getN() {
		return this.n;
	}
}
