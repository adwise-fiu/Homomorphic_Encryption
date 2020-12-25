package security.DGK;

import java.security.Provider;

public class DGKProvider extends Provider
{
	private static final long serialVersionUID = 7535524512688509040L;

	public DGKProvider() 
	{
		 super("DGK", 1.0, "DGK v1.0");
		 put("KeyPairGenerator.DGK", DGKKeyPairGenerator.class.getName());
		 put("Cipher.DGK", DGKOperations.class.getName());
		 put("Signture.DGK", DGKSignature.class.getName());
		 // put("KeyFactory.DGK", DGKKeyFactory.class.getName());
	}
}
