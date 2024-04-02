package security.socialistmillionaire;

import security.dgk.DGKOperations;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class bob_veugen extends bob {
    private static final Logger logger = LogManager.getLogger(bob_veugen.class);

    public bob_veugen(KeyPair a, KeyPair b, KeyPair c) throws IllegalArgumentException {
        super(a, b, c);
    }

    public bob_veugen(KeyPair a, KeyPair b) throws IllegalArgumentException {
        super(a, b);
    }

    // Use this for Using Modified Protocol3 within Protocol 4
    boolean Modified_Protocol3(BigInteger beta, BigInteger z)
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {

        BigInteger d;
        BigInteger N;

        if(isDGK) {
            N = dgk_public.getU();
        }
        else {
            N = paillier_public.getN();
        }

        // Step A: z < (N - 1)/2
        if(z.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) < 0) {
            d = DGKOperations.encrypt(1, dgk_public);
        }
        else {
            d = DGKOperations.encrypt(0, dgk_public);
        }
        writeObject(d);
        return Protocol1(beta);
    }

    /**
     * Please review Correction to Improving the DGK comparison protocol - Protocol 3
     */
    public boolean Protocol2()
            throws IOException, ClassNotFoundException, HomomorphicException {
        // Constraint for Paillier
        if(!isDGK && dgk_public.getL() + 2 >= paillier_public.key_size) {
            throw new IllegalArgumentException("Constraint violated: l + 2 < log_2(N)");
        }

        Object x;
        BigInteger beta;
        BigInteger z;
        BigInteger zeta_one;
        BigInteger zeta_two;

        //Step 1: get [[z]] from Alice
        x = readObject();
        if (x instanceof BigInteger) {
            z = (BigInteger) x;
        }
        else {
            throw new IllegalArgumentException("Protocol 4: No BigInteger found! " + x.getClass().getName());
        }

        if(isDGK) {
            z = BigInteger.valueOf(DGKOperations.decrypt(z, dgk_private));
        }
        else {
            z = PaillierCipher.decrypt(z, paillier_private);
        }

        // Step 2: compute Beta = z (mod 2^l),
        beta = NTL.POSMOD(z, powL);

        // Step 3: Alice computes r (mod 2^l) (Alpha)
        // Step 4: Run Modified DGK Comparison Protocol
        // true --> run Modified protocol 3

        if(readBoolean()) {
            if(Modified_Protocol3(beta, z)) {
                logger.info("Modified Protocol 3 selected");
            }
        }
        else {
            Protocol1(beta);
        }

        //Step 5" Send [[z/2^l]], Alice has the solution from Protocol 3 already
        if(isDGK) {
            zeta_one = DGKOperations.encrypt(z.divide(powL), dgk_public);
            if(z.compareTo(dgk_public.getU().subtract(BigInteger.ONE).divide(TWO)) < 0) {
                zeta_two = DGKOperations.encrypt(z.add(dgk_public.getU()).divide(powL), dgk_public);
            }
            else {
                zeta_two = DGKOperations.encrypt(z.divide(powL), dgk_public);
            }
        }
        else
        {
            zeta_one = PaillierCipher.encrypt(z.divide(powL), paillier_public);
            if(z.compareTo(paillier_public.getN().subtract(BigInteger.ONE).divide(TWO)) < 0) {
                zeta_two = PaillierCipher.encrypt(z.add(dgk_public.getN()).divide(powL), paillier_public);
            }
            else {
                zeta_two =  PaillierCipher.encrypt(z.divide(powL), paillier_public);
            }
        }
        toAlice.writeObject(zeta_one);
        toAlice.writeObject(zeta_two);
        toAlice.flush();

        //Step 6 - 7: Alice Computes [[x >= y]]

        //Step 8 (UNOFFICIAL): Alice needs the answer...
        return decrypt_protocol_two();
    }
}
