package test;

import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamal_Ciphertext;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.socialistmillionaire.alice_elgamal;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class test_el_gamal_alice implements constants, Runnable {
    private static final Logger logger = LogManager.getLogger(test_el_gamal_alice.class);

    public test_el_gamal_alice(alice_elgamal Niu, ElGamalPrivateKey el_gamal_private) {
        this.Niu = Niu;
        this.el_gamal_private = el_gamal_private;
    }

    private final alice_elgamal Niu;
    private ElGamalPublicKey el_gamal_public;
    private final ElGamalPrivateKey el_gamal_private;

    // Get your test data...
    private static final BigInteger[] low = IntegrationTests.generate_low();
    private static final BigInteger [] mid = IntegrationTests.generate_mid();
    private static final BigInteger [] high = IntegrationTests.generate_high();

    public void run() {
        try {
            el_gamal_public = Niu.getElGamalPublicKey();
            test_sorting();
            test_protocol_two();
            test_outsourced_multiply();
            test_outsourced_division();

            //Niu.set_el_gamal_additive(false);
            //el_gamal_private.set_additive(false);
            ///el_gamal_public.set_additive(false);
            //test_addition();
            //test_subtract();
        }
        catch (ClassNotFoundException | HomomorphicException | IOException e) {
            logger.error(e.getStackTrace());
        }
    }

    public void test_sorting() throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("Alice: Sorting Test...ElGamal");
        BigInteger [] toSort = new BigInteger[low.length];
        List<ElGamal_Ciphertext> t = new ArrayList<>();
        List<ElGamal_Ciphertext> min;
        BigInteger [] plain_min = new BigInteger[3];

        // Test ElGamal Sorting
        for(int i = 0; i < low.length;i++) {
            toSort[i] = NTL.generateXBitRandom(9);
            t.add(ElGamalCipher.encrypt(toSort[i], el_gamal_public));
        }
        if(el_gamal_public.additive) {
            min = Niu.getKMin(t, 3);
            for (int i = 0; i < 3; i++) {
                plain_min[i] = ElGamalCipher.decrypt(min.get(i), el_gamal_private);
            }
        }
        // Use assert to sort array
        Arrays.sort(toSort);
        for (int i = 0; i < plain_min.length; i++) {
            assertEquals(toSort[i], plain_min[i]);
        }
        logger.info("General List: " + Arrays.toString(toSort));
        logger.info("Three minimum numbers: " + Arrays.toString(plain_min));
    }

    public void test_protocol_two() throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("Alice: Protocol 4 Tests...ElGamal");
        boolean answer;
        // Test for X >= Y
        for (int i = 0; i < low.length;i++) {
            answer = Niu.Protocol4(ElGamalCipher.encrypt(low[i], el_gamal_public),
                    ElGamalCipher.encrypt(mid[i], el_gamal_public));
            assertFalse(answer);
            answer = Niu.Protocol4(ElGamalCipher.encrypt(mid[i], el_gamal_public),
                    ElGamalCipher.encrypt(mid[i], el_gamal_public));
            assertTrue(answer);
            answer = Niu.Protocol4(ElGamalCipher.encrypt(high[i], el_gamal_public),
                    ElGamalCipher.encrypt(mid[i], el_gamal_public));
            assertTrue(answer);
        }
    }

    public void test_outsourced_multiply() throws IOException, ClassNotFoundException {
        logger.info("Alice: Multiplication Tests...ElGamal");
        ElGamal_Ciphertext temp;
        // Check the multiplication, ElGamal
        temp = Niu.multiplication(ElGamalCipher.encrypt(THOUSAND, el_gamal_public),
                ElGamalCipher.encrypt(TWO, el_gamal_public));
        assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), TWO_THOUSAND);
        temp = Niu.multiplication(ElGamalCipher.encrypt(THOUSAND, el_gamal_public),
                ElGamalCipher.encrypt(THREE, el_gamal_public));
        assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), THREE_THOUSAND);
        temp = Niu.multiplication(ElGamalCipher.encrypt(THOUSAND, el_gamal_public),
                ElGamalCipher.encrypt(FIFTY, el_gamal_public));
        assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), FIFTY_THOUSAND);
    }

    public void test_outsourced_division()
            throws HomomorphicException, IOException, ClassNotFoundException {
        logger.info("Division Tests...ElGamal");
        ElGamal_Ciphertext big = ElGamalCipher.encrypt(100, el_gamal_public);
        ElGamal_Ciphertext temp;
        temp = Niu.division(big, 2);//100/2 = 50
        assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), FIFTY);

        temp = Niu.division(big, 3);//100/3 = 33
        assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), THIRTY_THREE);

        temp = Niu.division(big, 4);//100/4 = 25
        assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), TWENTY_FIVE);

        temp = Niu.division(big, 5);//100/5 = 20
        assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), TWENTY);

        temp = Niu.division(big, 25);//100/25 = 4
        assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), FOUR);
    }

    public void test_addition() throws IOException, ClassNotFoundException {
        ElGamal_Ciphertext temp;
        if (!el_gamal_public.additive) {
            logger.info("Alice: Test ElGamal Secure Addition...");
            temp = Niu.addition(ElGamalCipher.encrypt(TWO_HUNDRED, el_gamal_public),
                    ElGamalCipher.encrypt(HUNDRED, el_gamal_public));
            assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), THREE_HUNDRED);

            temp = Niu.addition(ElGamalCipher.encrypt(FOUR_HUNDRED, el_gamal_public),
                    ElGamalCipher.encrypt(HUNDRED, el_gamal_public));
            assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), FIVE_HUNDRED);

            temp = Niu.addition(ElGamalCipher.encrypt(THOUSAND, el_gamal_public),
                    ElGamalCipher.encrypt(THOUSAND, el_gamal_public));
            assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), TWO_THOUSAND);
        }
    }

    public void test_subtract() throws IOException, ClassNotFoundException {
        ElGamal_Ciphertext temp;
        if (!el_gamal_public.additive) {
            logger.info("Alice: Test ElGamal Secure Subtraction...");
            temp = Niu.addition(ElGamalCipher.encrypt(TWO_HUNDRED, el_gamal_public),
                    ElGamalCipher.encrypt(HUNDRED, el_gamal_public));
            assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), HUNDRED);

            temp = Niu.addition(ElGamalCipher.encrypt(FOUR_HUNDRED, el_gamal_public),
                    ElGamalCipher.encrypt(HUNDRED, el_gamal_public));
            assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), THREE_HUNDRED);

            temp = Niu.addition(ElGamalCipher.encrypt(THOUSAND, el_gamal_public),
                    ElGamalCipher.encrypt(THOUSAND, el_gamal_public));
            assertEquals(ElGamalCipher.decrypt(temp, el_gamal_private), BigInteger.ZERO);
        }
    }
}
