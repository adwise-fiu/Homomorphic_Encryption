package security.elgamal;

import java.security.Provider;

public class ElGamalProvider extends Provider
{
	private static final long serialVersionUID = 7535524512688509040L;

	public ElGamalProvider() 
	{
		 super("ElGamal", 1.0, "ElGamal v1.0");
		 put("KeyPairGenerator.ElGamal", ElGamalKeyPairGenerator.class.getName());
		 put("Cipher.ElGamal", ElGamalCipher.class.getName());
		 put("Signture.ElGamal", ElGamalSignature.class.getName());
		 // put("KeyFactory.ElGamal", ElGamalKeyFactory.class.getName());
	}
}
