package security.paillier;

import java.security.Provider;

/*
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
*/

public class PaillierProvider extends Provider 
{
	private static final long serialVersionUID = -6926028291417830360L;

	public PaillierProvider() 
	{
		super("Paillier", 1.0, "Paillier v 1.0");
		put("KeyPairGenerator.Paillier", PaillierKeyPairGenerator.class.getName());
		put("Cipher.Paillier", PaillierCipher.class.getName());
		put("Signture.Paillier", PaillierSignature.class.getName());
		// put("KeyFactory.Paillier", PaillierKeyFactory.class.getName());
	}
}