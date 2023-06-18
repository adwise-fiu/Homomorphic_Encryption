package test;

import org.junit.BeforeClass;
import org.junit.Test;
import security.elgamal.*;
import security.misc.HomomorphicException;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class ElGamalAdd implements constants {
    private static ElGamalPublicKey public_key;
    private static ElGamalPrivateKey private_key;
    private static ElGamal_Ciphertext a;

    @BeforeClass
    public static void generate_keys() {
        ElGamalKeyPairGenerator pa = new ElGamalKeyPairGenerator(true);
        pa.initialize(KEY_SIZE, null);
        KeyPair paillier = pa.generateKeyPair();
        public_key = (ElGamalPublicKey) paillier.getPublic();
        private_key = (ElGamalPrivateKey) paillier.getPrivate();
    }

    @Test
    public void test_decrypt() {
        // Test D(E(X)) = X
        ElGamal_Ciphertext a = ElGamalCipher.encrypt(BigInteger.TEN, public_key);
        BigInteger alpha = ElGamalCipher.decrypt(a, private_key);
        assertEquals(BigInteger.TEN, alpha);
    }

    @Test
    public void test_addition() {
        // Test Addition
        a = ElGamalCipher.encrypt(BigInteger.TEN, public_key);
        a = ElGamalCipher.add(a, a, public_key); //20
        assertEquals(TWENTY, ElGamalCipher.decrypt(a, private_key));
    }

    @Test
    public void test_multiply() {
        // Test Multiplication
        a = ElGamalCipher.encrypt(BigInteger.TEN, public_key);
        a = ElGamalCipher.multiply_scalar(a, BigInteger.TEN, public_key); // 10 * 10
        assertEquals(HUNDRED, ElGamalCipher.decrypt(a, private_key));
    }

    @Test
    public void test_subtract() {
        a = ElGamalCipher.subtract(ElGamalCipher.encrypt(TWENTY, public_key),
                ElGamalCipher.encrypt(BigInteger.TEN, public_key), public_key);// 20 - 10
        assertEquals(BigInteger.TEN, ElGamalCipher.decrypt(a, private_key));
    }

    @Test
    public void test_divide() {

    }

    @Test
    public void test_sum() throws HomomorphicException {
        ElGamal_Ciphertext [] values = new ElGamal_Ciphertext[10];
        List<ElGamal_Ciphertext> list_values = new ArrayList<>();

        // sum with arrays
        for (int i = 0; i < values.length; i++) {
            values[i] = ElGamalCipher.encrypt(BigInteger.TEN, public_key);
            list_values.add(ElGamalCipher.encrypt(BigInteger.TEN, public_key));
        }

        a = ElGamalCipher.sum(values, public_key, 11);
        assertEquals(HUNDRED, ElGamalCipher.decrypt(a, private_key));

        a = ElGamalCipher.sum(values, public_key, 5);
        assertEquals(FIFTY, ElGamalCipher.decrypt(a, private_key));

        // sum with lists
        a = ElGamalCipher.sum(list_values, public_key, 11);
        assertEquals(HUNDRED, ElGamalCipher.decrypt(a, private_key));

        a = ElGamalCipher.sum(list_values, public_key, 5);
        assertEquals(FIFTY, ElGamalCipher.decrypt(a, private_key));
    }

    // NOTE: THIS IS THE ADDITIVE VERSION
    @Test
    public void test_product_sum() throws HomomorphicException {
        ElGamal_Ciphertext [] encrypted_values = new ElGamal_Ciphertext[10];
        Long [] plain_values = new Long[10];
        List<ElGamal_Ciphertext> encrypted_list_values = new ArrayList<>();
        List<Long> plain_list_values = new ArrayList<>();

        // Initialize
        for (int i = 0; i < encrypted_values.length; i++) {
            encrypted_values[i] = ElGamalCipher.encrypt(BigInteger.TEN, public_key);
            plain_values[i] = TWO.longValue();

            encrypted_list_values.add(ElGamalCipher.encrypt(BigInteger.TEN, public_key));
            plain_list_values.add(TWO.longValue());
        }

        // sum with lists
        a = ElGamalCipher.sum_product(encrypted_values, plain_values, public_key);
        assertEquals(ElGamalCipher.decrypt(a, private_key), TWO_HUNDRED);

        a = ElGamalCipher.sum_product(encrypted_list_values, plain_list_values, public_key);
        assertEquals(ElGamalCipher.decrypt(a, private_key), TWO_HUNDRED);
    }
}
