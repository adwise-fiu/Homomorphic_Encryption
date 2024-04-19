package security.elgamal;

import java.io.Serial;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public final class ElGamalPublicKey implements Serializable, PublicKey, ElGamal_Key
{
	@Serial
	private static final long serialVersionUID = -6796919675914392847L;
	final BigInteger p;
	final BigInteger g;
	final BigInteger h;
	public boolean additive;

	public ElGamalPublicKey(BigInteger p, BigInteger g, BigInteger h, boolean additive) {
		this.p = p;
		this.g = g;
		this.h = h;
		this.additive = additive;
	}

	public void set_additive(boolean additive) {
		this.additive = additive;
	}

	public String getAlgorithm() {
		return "ElGamal";
	}

	public String getFormat() {
		return "X.509";
	}

	public byte[] getEncoded() {
		return null;
	}

	public BigInteger getP() {
		return this.p;
	}

	public String toString() {
		String answer = "";
		answer += "p=" + this.p + '\n';
		answer += "g=" + this.g + '\n';
		answer += "h=" + this.h + '\n';
		return answer;
	}
}
