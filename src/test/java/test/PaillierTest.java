package test;

import org.junit.BeforeClass;
import org.junit.Test;

import security.misc.HomomorphicException;
import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

import java.math.BigInteger;
import java.security.KeyPair;

import static org.junit.Assert.*;

public class PaillierTest {

    private static final int KEY_SIZE = 1024;
    private static PaillierPublicKey public_key;
    private static PaillierPrivateKey private_key;

    @BeforeClass
    public static void generate_keys() {
        PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
        pa.initialize(KEY_SIZE, null);
        KeyPair paillier = pa.generateKeyPair();
        public_key = (PaillierPublicKey) paillier.getPublic();
        private_key = (PaillierPrivateKey) paillier.getPrivate();
    }

    @Test
    public void basic_Paillier() throws HomomorphicException {
        // Test D(E(X)) = X
        BigInteger a;
        a = PaillierCipher.decrypt(PaillierCipher.encrypt(BigInteger.TEN, public_key), private_key);
        assertEquals(BigInteger.TEN, a);

        // Test Addition
        a = PaillierCipher.encrypt(BigInteger.TEN, public_key);
        a = PaillierCipher.add(a, a, public_key); // 20
        assertEquals(new BigInteger("20"), PaillierCipher.decrypt(a, private_key));

        // Test addition, cipher-text and plain-text (private_keyip encryption)
        a = PaillierCipher.encrypt(BigInteger.TEN, public_key);
        a = PaillierCipher.add_plaintext(a, BigInteger.TEN, public_key);
        assertEquals(new BigInteger("20"), PaillierCipher.decrypt(a, private_key));

        // Test Subtraction
        a = PaillierCipher.subtract(PaillierCipher.encrypt(new BigInteger("20"), public_key),
                PaillierCipher.encrypt(BigInteger.TEN, public_key), public_key);// 20 - 10
        assertEquals(BigInteger.TEN, PaillierCipher.decrypt(a, private_key));

        // Test Subtraction plaintext
		/*
		a = PaillierCipher.subtract_plaintext(PaillierCipher.encrypt(new BigInteger("20"), public_key),
				BigInteger.TEN, public_key);// 20 - 10
		assertEquals(BigInteger.TEN, PaillierCipher.decrypt(a, private_key));
		*/

        // Test Multiplication
        a = PaillierCipher.multiply(PaillierCipher.encrypt(BigInteger.TEN, public_key),
                BigInteger.TEN, public_key); // 10 * 10
        assertEquals(new BigInteger("100"), PaillierCipher.decrypt(a, private_key));

        // Test Division
        a = PaillierCipher.divide(PaillierCipher.encrypt(new BigInteger("100"), public_key),
                new BigInteger("2"), public_key); // 100/2
        assertEquals(new BigInteger("50"), PaillierCipher.decrypt(a, private_key));
    }
}
