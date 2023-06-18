package test;

import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamalPrivateKey;
import security.elgamal.ElGamalPublicKey;
import security.elgamal.ElGamal_Ciphertext;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;
import security.socialistmillionaire.alice;
import security.socialistmillionaire.alice_veugen;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class test_el_gamal_alice implements constants {
    public test_el_gamal_alice(alice_veugen Niu) {
        this.Niu = Niu;
    }

    private final alice_veugen Niu;
    private static PaillierPublicKey paillier_public;
    private static DGKPublicKey dgk_public_key;
    private static ElGamalPublicKey el_gamal_public;

    private static PaillierPrivateKey paillier_private;
    private static DGKPrivateKey privKey;
    private static ElGamalPrivateKey e_paillier_private;

    // Get your test data...
    private static final BigInteger[] low = IntegrationTests.generate_low();
    private static final BigInteger [] mid = IntegrationTests.generate_mid();
    private static final BigInteger [] high = IntegrationTests.generate_high();

    public void run() {
        try {
            paillier_public = Niu.getPaillierPublicKey();
            dgk_public_key = Niu.getDGKPublicKey();
            el_gamal_public = Niu.getElGamalPublicKey();

            // Get Private Keys from Bob
            // This is only for verifying tests...
            paillier_private = (PaillierPrivateKey) Niu.readObject();
            privKey = (DGKPrivateKey) Niu.readObject();
            e_paillier_private = (ElGamalPrivateKey) Niu.readObject();

            test_sorting();

            test_protocol_two();
            test_outsourced_multiply();
            test_outsourced_division();

        }
        catch (ClassNotFoundException | IOException | HomomorphicException e) {
            e.printStackTrace();
        }
    }

    public void test_sorting() throws HomomorphicException, IOException, ClassNotFoundException {
        BigInteger [] toSort = new BigInteger[low.length];
        List<ElGamal_Ciphertext> t = new ArrayList<>();

        // Test ElGamal Sorting
        for(int i = 0; i < low.length;i++) {
            toSort[i] = NTL.generateXBitRandom(9);
            t.add(ElGamalCipher.encrypt(toSort[i], el_gamal_public));
        }
        if(el_gamal_public.ADDITIVE) {
            Niu.getKMin_ElGamal(t, 3);
        }
    }

    public void test_protocol_two() throws HomomorphicException, IOException, ClassNotFoundException {
        System.out.println("Protocol 4 Tests...ElGamal");
        for (int i = 0; i < low.length;i++) {
            System.out.println(!Niu.Protocol4(ElGamalCipher.encrypt(low[i], el_gamal_public),
                    ElGamalCipher.encrypt(mid[i], el_gamal_public)));
            System.out.println(Niu.Protocol4(ElGamalCipher.encrypt(mid[i], el_gamal_public),
                    ElGamalCipher.encrypt(mid[i], el_gamal_public)));
            System.out.println(Niu.Protocol4(ElGamalCipher.encrypt(high[i], el_gamal_public),
                    ElGamalCipher.encrypt(mid[i], el_gamal_public)));
        }
    }

    public void test_outsourced_multiply() throws IOException, ClassNotFoundException {
        System.out.println("Multiplication Tests...ElGamal");
        // Check the multiplication, ElGamal
        Niu.multiplication(ElGamalCipher.encrypt(THOUSAND, el_gamal_public),
                ElGamalCipher.encrypt(TWO, el_gamal_public));
        Niu.multiplication(ElGamalCipher.encrypt(THOUSAND, el_gamal_public),
                ElGamalCipher.encrypt(THREE, el_gamal_public));
        Niu.multiplication(ElGamalCipher.encrypt(THOUSAND, el_gamal_public),
                ElGamalCipher.encrypt(FIFTY, el_gamal_public));
    }

    public void test_outsourced_division()
            throws HomomorphicException, IOException, ClassNotFoundException {
        System.out.println("Division Tests...ElGamal");
        Niu.division(ElGamalCipher.encrypt(160, el_gamal_public), 2);//160/2 = 50
        Niu.division(ElGamalCipher.encrypt(160, el_gamal_public), 3);//160/3 = 33
        Niu.division(ElGamalCipher.encrypt(160, el_gamal_public), 4);//160/4 = 25
        Niu.division(ElGamalCipher.encrypt(160, el_gamal_public), 5);//160/5 = 20
        Niu.division(ElGamalCipher.encrypt(160, el_gamal_public), 25);//160/25 = 4
    }

    public void test_addition() throws IOException, ClassNotFoundException {
        if (!el_gamal_public.ADDITIVE) {
            System.out.println("ElGamal Secure Addition: ");
            // Addition
            Niu.addition(ElGamalCipher.encrypt(HUNDRED, el_gamal_public), ElGamalCipher.encrypt(new BigInteger("160"), el_gamal_public));
            Niu.addition(ElGamalCipher.encrypt(new BigInteger("400"), el_gamal_public), ElGamalCipher.encrypt(new BigInteger("400"), el_gamal_public));
            Niu.addition(ElGamalCipher.encrypt(new BigInteger("1000"), el_gamal_public), ElGamalCipher.encrypt(new BigInteger("1600"), el_gamal_public));
        }
    }

    public void test_subtract() throws IOException, ClassNotFoundException {
        if (!el_gamal_public.ADDITIVE) {
            // Subtract
            Niu.addition(ElGamalCipher.encrypt(HUNDRED, el_gamal_public), ElGamalCipher.encrypt(new BigInteger("160"), el_gamal_public));
            Niu.addition(ElGamalCipher.encrypt(new BigInteger("400"), el_gamal_public), ElGamalCipher.encrypt(new BigInteger("160"), el_gamal_public));
            Niu.addition(ElGamalCipher.encrypt(new BigInteger("1000"), el_gamal_public), ElGamalCipher.encrypt(new BigInteger("160"), el_gamal_public));
        }
    }
}
