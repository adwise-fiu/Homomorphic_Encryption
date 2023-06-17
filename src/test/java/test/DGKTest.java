package test;

import org.junit.BeforeClass;
import org.junit.Test;
import security.dgk.DGKKeyPairGenerator;
import security.dgk.DGKOperations;
import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.misc.HomomorphicException;

import java.math.BigInteger;
import java.security.KeyPair;

import static org.junit.Assert.assertEquals;

public class DGKTest implements constants {
    private static DGKPublicKey public_key;
    private static DGKPrivateKey private_key;

    @BeforeClass
    public static void generate_keys() {
        DGKKeyPairGenerator pa = new DGKKeyPairGenerator();
        pa.initialize(KEY_SIZE, null);
        KeyPair dgk = pa.generateKeyPair();
        public_key = (DGKPublicKey) dgk.getPublic();
        private_key = (DGKPrivateKey) dgk.getPrivate();
    }

    @Test
    public void basic_DGK() throws HomomorphicException {
        // Test D(E(X)) = X
        BigInteger a = DGKOperations.encrypt(BigInteger.TEN, public_key);
        a = BigInteger.valueOf(DGKOperations.decrypt(a, private_key));
        assertEquals(BigInteger.TEN, a);

        // Test Addition, note decrypting returns a long not BigInteger
        a = DGKOperations.encrypt(a, public_key);
        a = DGKOperations.add(a, a, public_key); //20
        assertEquals(20, DGKOperations.decrypt(a, private_key));

        // Test Subtraction, note decrypting returns a long not BigInteger
        a = DGKOperations.subtract(a, DGKOperations.encrypt(BigInteger.TEN, public_key), public_key);// 20 - 10
        assertEquals(10, DGKOperations.decrypt(a, private_key));

        // Test Multiplication, note decrypting returns a long not BigInteger
        a = DGKOperations.multiply(a, BigInteger.TEN, public_key); // 10 * 10
        assertEquals(100, DGKOperations.decrypt(a, private_key));

        // Test Division, Division is failing for some reason...?
        a = DGKOperations.divide(a, TWO, public_key); // 100/2
        assertEquals(50, DGKOperations.decrypt(a, private_key));
    }
}
