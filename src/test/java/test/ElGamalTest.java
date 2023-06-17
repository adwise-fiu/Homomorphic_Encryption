package test;

import org.junit.BeforeClass;
import org.junit.Test;
import security.elgamal.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;


import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;

public class ElGamalTest implements constants {
    private static ElGamalPublicKey public_key;
    private static ElGamalPrivateKey private_key;

    @BeforeClass
    public static void generate_keys() {
        ElGamalKeyPairGenerator pa = new ElGamalKeyPairGenerator();
        pa.initialize(KEY_SIZE, null);
        KeyPair paillier = pa.generateKeyPair();
        public_key = (ElGamalPublicKey) paillier.getPublic();
        private_key = (ElGamalPrivateKey) paillier.getPrivate();
    }

    // NOTE: THIS IS THE MULTIPLICATIVE VERSION
    @Test
    public void basic_ElGamal_multiply() {
        // Build DGK Keys
        ElGamalKeyPairGenerator p = new ElGamalKeyPairGenerator();
        p.initialize(KEY_SIZE, new SecureRandom());
        KeyPair pe = p.generateKeyPair();

        ElGamalPublicKey pk = (ElGamalPublicKey) pe.getPublic();
        ElGamalPrivateKey sk = (ElGamalPrivateKey) pe.getPrivate();

        // Test D(E(X)) = X
        ElGamal_Ciphertext a = ElGamalCipher.encrypt(BigInteger.TEN, pk);
        BigInteger alpha = ElGamalCipher.decrypt(a, sk);
        assertEquals(BigInteger.TEN, alpha);

        // Test Multiplication
        // Can multiply two cipher-texts and store product of ciphers
        a = ElGamalCipher.multiply(a, ElGamalCipher.encrypt(BigInteger.TEN, pk), pk); // 10 * 10
        assertEquals(HUNDRED, ElGamalCipher.decrypt(a, sk));

        // Test Division
        a = ElGamalCipher.divide(a, ElGamalCipher.encrypt(TWO, pk), pk); // 100/2
        assertEquals(FIFTY, ElGamalCipher.decrypt(a, sk));
    }

    // NOTE: THIS IS THE ADDITIVE VERSION
    @Test
    public void basic_ElGamal_add() {
        // Test D(E(X)) = X
        ElGamal_Ciphertext a = ElGamalCipher.encrypt(BigInteger.TEN, public_key);
        BigInteger alpha = ElGamalCipher.decrypt(a, private_key);
        assertEquals(BigInteger.TEN, alpha);

        // Test Addition
        a = ElGamalCipher.encrypt(BigInteger.TEN, public_key);
        a = ElGamalCipher.add(a, a, public_key); //20
        assertEquals(TWENTY, ElGamalCipher.decrypt(a, private_key));

        // Test Subtraction
        a = ElGamalCipher.subtract(a, ElGamalCipher.encrypt(BigInteger.TEN, public_key), public_key);// 20 - 10
        assertEquals(BigInteger.TEN, ElGamalCipher.decrypt(a, private_key));

        // Test Multiplication
        a = ElGamalCipher.multiply_scalar(a, BigInteger.TEN, public_key); // 10 * 10
        assertEquals(new BigInteger("100"), ElGamalCipher.decrypt(a, private_key));

        // Test Division - INVALID FOR ADDITIVE MODE
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
