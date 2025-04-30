/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package test;

import edu.fiu.adwise.homomorphic_encryption.paillier.*;
import org.junit.BeforeClass;
import org.junit.Test;

import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class PaillierTest implements constants {

    private static PaillierPublicKey public_key;
    private static PaillierPrivateKey private_key;
    private BigInteger a;

    @BeforeClass
    public static void generate_keys() {
        PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
        pa.initialize(KEY_SIZE, null);
        KeyPair paillier = pa.generateKeyPair();
        public_key = (PaillierPublicKey) paillier.getPublic();
        private_key = (PaillierPrivateKey) paillier.getPrivate();
    }

    @Test
    public void test_decrypt() throws HomomorphicException {
        // Test D(E(X)) = X
        a = PaillierCipher.decrypt(PaillierCipher.encrypt(BigInteger.TEN, public_key), private_key);
        assertEquals(BigInteger.TEN, a);
    }

    @Test
    public void test_addition() throws HomomorphicException {
        // Test Addition
        a = PaillierCipher.encrypt(BigInteger.TEN, public_key);
        a = PaillierCipher.add(a, a, public_key); // 20
        assertEquals(TWENTY, PaillierCipher.decrypt(a, private_key));

        // Test addition, cipher-text and plain-text
        a = PaillierCipher.encrypt(BigInteger.TEN, public_key);
        a = PaillierCipher.add_plaintext(a, BigInteger.TEN, public_key);
        assertEquals(TWENTY, PaillierCipher.decrypt(a, private_key));
    }

    @Test
    public void test_multiply() throws HomomorphicException {
        // Test Multiplication
        a = PaillierCipher.multiply(PaillierCipher.encrypt(BigInteger.TEN, public_key),
                BigInteger.TEN, public_key); // 10 * 10
        assertEquals(HUNDRED, PaillierCipher.decrypt(a, private_key));
    }

    @Test
    public void test_subtract() throws HomomorphicException {
        // Test Subtraction
        a = PaillierCipher.encrypt(TWENTY, public_key);
        a = PaillierCipher.subtract(a, PaillierCipher.encrypt(BigInteger.TEN, public_key),
                public_key);// 20 - 10
        assertEquals(BigInteger.TEN, PaillierCipher.decrypt(a, private_key));

        // Test Subtraction plaintext
		a = PaillierCipher.subtract_plaintext(PaillierCipher.encrypt(TWENTY, public_key),
				BigInteger.TEN, public_key);// 20 - 10
		assertEquals(BigInteger.TEN, PaillierCipher.decrypt(a, private_key));

        // Test Subtraction with ciphertext
        a = PaillierCipher.subtract_ciphertext(FIFTY, PaillierCipher.encrypt(TWENTY, public_key), public_key);
        assertEquals(THIRTY, PaillierCipher.decrypt(a, private_key));
    }

    @Test
    public void test_divide() throws HomomorphicException {
        // Test Division
        a = PaillierCipher.divide(PaillierCipher.encrypt(HUNDRED, public_key), TWO, public_key); // 100/2
        assertEquals(FIFTY, PaillierCipher.decrypt(a, private_key));
    }

    @Test
    public void paillier_test_sum() throws HomomorphicException {

        BigInteger [] values = new BigInteger[10];
        List<BigInteger> list_values = new ArrayList<>();

        // sum with arrays
        for (int i = 0; i < values.length; i++) {
            values[i] = PaillierCipher.encrypt(BigInteger.TEN, public_key);
            list_values.add(PaillierCipher.encrypt(BigInteger.TEN, public_key));
        }

        a = PaillierCipher.sum(values, public_key, 11);
        assertEquals(HUNDRED, PaillierCipher.decrypt(a, private_key));

        a = PaillierCipher.sum(values, public_key, 5);
        assertEquals(FIFTY, PaillierCipher.decrypt(a, private_key));

        // sum with lists
        a = PaillierCipher.sum(list_values, public_key, 11);
        assertEquals(HUNDRED, PaillierCipher.decrypt(a, private_key));

        a = PaillierCipher.sum(list_values, public_key, 5);
        assertEquals(FIFTY, PaillierCipher.decrypt(a, private_key));
    }

    // This was used in the SST REU project
    @Test
    public void paillier_test_product_sum() throws HomomorphicException {
        // sum with arrays
        BigInteger [] encrypted_values = new BigInteger[10];
        Long [] plain_values = new Long[10];
        List<BigInteger> encrypted_list_values = new ArrayList<>();
        List<Long> plain_list_values = new ArrayList<>();

        // Initialize
        for (int i = 0; i < encrypted_values.length; i++) {
            encrypted_values[i] = PaillierCipher.encrypt(BigInteger.TEN, public_key);
            plain_values[i] = TWO.longValue();

            encrypted_list_values.add(PaillierCipher.encrypt(BigInteger.TEN, public_key));
            plain_list_values.add(TWO.longValue());
        }

        // sum with lists
        a = PaillierCipher.sum_product(encrypted_values, plain_values, public_key);
        assertEquals(PaillierCipher.decrypt(a, private_key), TWO_HUNDRED);

        a = PaillierCipher.sum_product(encrypted_list_values, plain_list_values, public_key);
        assertEquals(PaillierCipher.decrypt(a, private_key), TWO_HUNDRED);
    }

    @Test
    public void paillier_signature() {
        // Paillier Signature
        List<BigInteger> signed_answer = PaillierSignature.sign(FORTY_TWO, private_key);

        // Test signatures
        for (int i = 0; i < 1000; i++) {
            boolean answer = PaillierSignature.verify(BigInteger.valueOf(i), signed_answer, public_key);
            if (i == 42) {
                assertTrue(answer);
            }
            else {
                assertFalse(answer);
            }
        }
    }

}
