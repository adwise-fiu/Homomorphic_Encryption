/*
 * Copyright (c) 2025 ADWISE Lab, Florida International University (FIU), AndrewQuijano
 * Licensed under the MIT License. See LICENSE file in the project root for details.
 */
package edu.fiu.adwise.encryption_test;

import org.junit.BeforeClass;
import org.junit.Test;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKKeyPairGenerator;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKPrivateKey;
import edu.fiu.adwise.homomorphic_encryption.dgk.DGKPublicKey;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierKeyPairGenerator;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierPrivateKey;
import edu.fiu.adwise.homomorphic_encryption.paillier.PaillierPublicKey;

import java.io.IOException;
import java.security.KeyPair;

import static org.junit.Assert.assertEquals;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UtilTest implements constants {
    private static final Logger logger = LogManager.getLogger(UtilTest.class);
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
    public void test_store_dgk() throws IOException, ClassNotFoundException {
        dgk_public_key.writeKey("dgk.pub");
        dgk_private_key.writeKey("dgk.priv");
        logger.info("DGK Write Key");

        DGKPublicKey other_dgk_pub = DGKPublicKey.readKey("dgk.pub");
        logger.info("DGK Public Read");
        DGKPrivateKey other_dgk_private = DGKPrivateKey.readKey("dgk.priv");
        logger.info("DGK Public Read");

        assertEquals(dgk_public_key, other_dgk_pub);
        assertEquals(dgk_private_key, other_dgk_private);
        logger.info("READ/WRITE TEST ON DGK DONE");
    }

    @Test
    public void test_store_paillier() throws IOException, ClassNotFoundException {
        paillier_public_key.writeKey("paillier.pub");
        paillier_private_key.writeKey("paillier.priv");

        PaillierPublicKey other_paillier_pub = PaillierPublicKey.readKey("paillier.pub");
        PaillierPrivateKey other_paillier_private = PaillierPrivateKey.readKey("paillier.priv");

        assertEquals(paillier_public_key, other_paillier_pub);
        assertEquals(paillier_private_key, other_paillier_private);
        logger.info("READ/WRITE TEST ON PAILLIER DONE");
    }
}
