package security.socialistmillionaire;

import java.math.BigInteger;
import java.security.SecureRandom;

import security.DGK.DGKPublicKey;
import security.elgamal.ElGamalPublicKey;
import security.paillier.PaillierPublicKey;

public abstract class socialist_millionaires 
{
	protected final static BigInteger TWO = new BigInteger("2");
	protected final SecureRandom rnd = new SecureRandom();
	protected final static int SIGMA = 80;
	protected final static int BILLION = BigInteger.TEN.pow(9).intValue();
	
	// Ensure Alice and Bob have the same settings!
	// May enable users to set this at Runtime?
	protected boolean USE_PROTOCOL_2 = false;
	protected boolean FAST_DIVIDE = false;
    protected boolean isDGK = false;
    
    // Both Alice and Bob will have keys
	protected PaillierPublicKey pk = null;
	protected DGKPublicKey pubKey = null;
	protected ElGamalPublicKey e_pk = null;
	
	// Both use 2^l
    protected BigInteger powL;
    
    public void setDGKMode(boolean isDGK)
    {
    	this.isDGK = isDGK;
    }
}
