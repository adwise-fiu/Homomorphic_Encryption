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
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class DGKTest implements constants {
    private static DGKPublicKey public_key;
    private static DGKPrivateKey private_key;

    private static BigInteger a;

    @BeforeClass
    public static void generate_keys() {
        DGKKeyPairGenerator pa = new DGKKeyPairGenerator();
        pa.initialize(KEY_SIZE, null);
        KeyPair dgk = pa.generateKeyPair();
        public_key = (DGKPublicKey) dgk.getPublic();
        private_key = (DGKPrivateKey) dgk.getPrivate();
    }

    @Test
    public void test_decrypt() throws HomomorphicException {
        // Test D(E(X)) = X
        BigInteger a = DGKOperations.encrypt(BigInteger.TEN, public_key);
        a = BigInteger.valueOf(DGKOperations.decrypt(a, private_key));
        assertEquals(BigInteger.TEN, a);
    }

    @Test
    public void test_addition() throws HomomorphicException {
        // Test Addition, note decrypting returns a long not BigInteger
        a = DGKOperations.encrypt(BigInteger.TEN, public_key);
        a = DGKOperations.add(a, a, public_key); //20
        assertEquals(20, DGKOperations.decrypt(a, private_key));

        // Test Addition, note decrypting returns a long not BigInteger
        a = DGKOperations.encrypt(BigInteger.TEN, public_key);
        a = DGKOperations.add_plaintext(a, BigInteger.TEN, public_key); //20
        assertEquals(20, DGKOperations.decrypt(a, private_key));
    }

    @Test
    public void test_multiply() throws HomomorphicException {
        // Test Multiplication, note decrypting returns a long not BigInteger
        a = DGKOperations.encrypt(BigInteger.TEN, public_key);
        a = DGKOperations.multiply(a, BigInteger.TEN, public_key); // 10 * 10
        assertEquals(100, DGKOperations.decrypt(a, private_key));
    }

    @Test
    public void test_subtract() throws HomomorphicException {
        // Test Subtraction with plaintext
        a = DGKOperations.subtract(DGKOperations.encrypt(TWENTY, public_key),
                DGKOperations.encrypt(BigInteger.TEN, public_key), public_key);// 20 - 10
        assertEquals(10, DGKOperations.decrypt(a, private_key));

        a = DGKOperations.subtract_plaintext(DGKOperations.encrypt(TWENTY, public_key),
                BigInteger.TEN, public_key);// 20 - 10
        assertEquals(10, DGKOperations.decrypt(a, private_key));

        // Test Subtraction with ciphertext
        a = DGKOperations.subtract_ciphertext(FIFTY, DGKOperations.encrypt(TWENTY, public_key), public_key);
        assertEquals(30, DGKOperations.decrypt(a, private_key));
    }
    @Test
    public void test_divide() throws HomomorphicException {
        // Test Division, Division is failing for some reason...?
        a = DGKOperations.divide(DGKOperations.encrypt(HUNDRED, public_key), TWO, public_key); // 100/2
        assertEquals(50, DGKOperations.decrypt(a, private_key));
    }

    @Test
    public void dgk_test_sum() throws HomomorphicException {

        BigInteger [] values = new BigInteger[10];
        List<BigInteger> list_values = new ArrayList<>();

        // sum with arrays
        for (int i = 0; i < values.length; i++) {
            values[i] = DGKOperations.encrypt(BigInteger.TEN, public_key);
            list_values.add(DGKOperations.encrypt(BigInteger.TEN, public_key));
        }

        a = DGKOperations.sum(values, public_key, 11);
        assertEquals(100, DGKOperations.decrypt(a, private_key));

        a = DGKOperations.sum(values, public_key, 5);
        assertEquals(50, DGKOperations.decrypt(a, private_key));

        // sum with lists
        a = DGKOperations.sum(list_values, public_key, 11);
        assertEquals(100, DGKOperations.decrypt(a, private_key));

        a = DGKOperations.sum(list_values, public_key, 5);
        assertEquals(50, DGKOperations.decrypt(a, private_key));
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
            encrypted_values[i] = DGKOperations.encrypt(BigInteger.TEN, public_key);
            plain_values[i] = TWO.longValue();

            encrypted_list_values.add(DGKOperations.encrypt(BigInteger.TEN, public_key));
            plain_list_values.add(TWO.longValue());
        }

        // sum with lists
        a = DGKOperations.sum_product(encrypted_values, plain_values, public_key);
        assertEquals(DGKOperations.decrypt(a, private_key), 200);

        a = DGKOperations.sum_product(encrypted_list_values, plain_list_values, public_key);
        assertEquals(DGKOperations.decrypt(a, private_key), 200);
    }
}
