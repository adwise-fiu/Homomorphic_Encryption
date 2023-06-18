package test;

import org.junit.BeforeClass;
import org.junit.Test;
import security.dgk.DGKKeyPairGenerator;
import security.dgk.DGKPrivateKey;
import security.dgk.DGKPublicKey;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPrivateKey;
import security.paillier.PaillierPublicKey;

import java.security.KeyPair;

import static org.junit.Assert.assertEquals;

public class UtilTest implements constants {
    private static PaillierPublicKey paillier_public_key;
    private static PaillierPrivateKey paillier_private_key;

    private static DGKPrivateKey dgk_private_key;

    private static DGKPublicKey dgk_public_key;

    @BeforeClass
    public static void generate_keys() {
        PaillierKeyPairGenerator pa = new PaillierKeyPairGenerator();
        pa.initialize(KEY_SIZE, null);
        KeyPair paillier = pa.generateKeyPair();
        paillier_public_key = (PaillierPublicKey) paillier.getPublic();
        paillier_private_key = (PaillierPrivateKey) paillier.getPrivate();

        DGKKeyPairGenerator dgk_generator = new DGKKeyPairGenerator();
        dgk_generator.initialize(KEY_SIZE, null);
        KeyPair dgk = dgk_generator.generateKeyPair();
        dgk_public_key = (DGKPublicKey) dgk.getPublic();
        dgk_private_key = (DGKPrivateKey) dgk.getPrivate();
    }

    @Test
    public void test_store_dgk() {
        dgk_public_key.writeKey("dgk.pub");
        dgk_private_key.writeKey("dgk");
        System.out.println("DGK Write Key");

        DGKPublicKey other_dgk_pub = DGKPublicKey.readKey("dgk.pub");
        System.out.println("DGK Public Read");
        DGKPrivateKey other_dgk_private = DGKPrivateKey.readKey("dgk");
        System.out.println("DGK Public Read");

        assertEquals(dgk_public_key, other_dgk_pub);
        assertEquals(dgk_private_key, other_dgk_private);
        System.out.println("READ/WRITE TEST ON DGK DONE");
    }

    @Test
    public void test_store_paillier() {
        paillier_public_key.writeKey("paillier.pub");
        paillier_private_key.writeKey("paillier");

        PaillierPublicKey other_paillier_pub = PaillierPublicKey.readKey("paillier.pub");
        PaillierPrivateKey other_paillier_private = PaillierPrivateKey.readKey("paillier");

        assertEquals(paillier_public_key, other_paillier_pub);
        assertEquals(paillier_private_key, other_paillier_private);
        System.out.println("READ/WRITE TEST ON PAILLIER DONE");
    }
}
