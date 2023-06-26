package test;

import org.junit.BeforeClass;
import org.junit.Test;
import security.elgamal.*;
import security.misc.HomomorphicException;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;


import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;

public class ElGamalMultiplyTest implements constants {
    private static ElGamalPublicKey public_key;
    private static ElGamalPrivateKey private_key;
    private static ElGamal_Ciphertext a;

    @BeforeClass
    public static void generate_keys() {
        ElGamalKeyPairGenerator pa = new ElGamalKeyPairGenerator(false);
        pa.initialize(EL_GAMAL_KEY_SIZE, new SecureRandom());
        KeyPair el_gamal = pa.generateKeyPair();
        public_key = (ElGamalPublicKey) el_gamal.getPublic();
        private_key = (ElGamalPrivateKey) el_gamal.getPrivate();
    }

    @Test
    public void test_decrypt() throws HomomorphicException {
        // Test D(E(X)) = X
        ElGamal_Ciphertext a = ElGamalCipher.encrypt(BigInteger.TEN, public_key);
        BigInteger alpha = ElGamalCipher.decrypt(a, private_key);
        assertEquals(BigInteger.TEN, alpha);
    }

    @Test
    public void test_multiply() {
        // Test Multiplication
        // Can multiply two cipher-texts and store product of ciphers
        a = ElGamalCipher.encrypt(BigInteger.TEN, public_key);
        a = ElGamalCipher.multiply(a, ElGamalCipher.encrypt(BigInteger.TEN, public_key), public_key); // 10 * 10
        assertEquals(HUNDRED, ElGamalCipher.decrypt(a, private_key));
    }

    // NOTE: THIS IS THE MULTIPLICATIVE VERSION
    @Test
    public void test_divide() {
        // Test Division
        a = ElGamalCipher.encrypt(HUNDRED, public_key);
        a = ElGamalCipher.divide(a, ElGamalCipher.encrypt(TWO, public_key), public_key); // 100/2
        assertEquals(FIFTY, ElGamalCipher.decrypt(a, private_key));
    }

    @Test
    public void el_gamal_signature() {
        // ElGamal Signature
        ElGamal_Ciphertext signed = ElGamalSignature.sign(FORTY_TWO, private_key);

        for (int i = 0; i < 1000; i++) {
            boolean answer = ElGamalSignature.verify(BigInteger.valueOf(i), signed, public_key);
            if (i == 42) {
                assertTrue(answer);
            }
            else {
                assertFalse(answer);
            }
        }
    }
}
