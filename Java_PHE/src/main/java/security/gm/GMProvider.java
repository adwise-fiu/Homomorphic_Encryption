package security.gm;

import java.security.Provider;

public class GMProvider extends Provider
{
	private static final long serialVersionUID = -8059198454993170815L;

	public GMProvider() 
	{
		 super("GM", "GM", "1.0");
		 put("KeyPairGenerator.GM", GMKeyPairGenerator.class.getName());
		 put("Cipher.GM", GMCipher.class.getName());
		 // put("KeyFactory.GM", GMKeyFactory.class.getName());
	}
}
