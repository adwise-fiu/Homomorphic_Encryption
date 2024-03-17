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
        Object in;
        BigInteger [] C;
        BigInteger [] beta_bits = new BigInteger[beta.bitLength()];
        BigInteger deltaA;
        BigInteger d;
        BigInteger N;
        int deltaB = 0;

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
        toAlice.writeObject(d);
        toAlice.flush();

        // Step B: Send the encrypted Beta bits
        for (int i = 0; i < beta_bits.length;i++) {
            beta_bits[i] = DGKOperations.encrypt(NTL.bit(beta, i), dgk_public);
        }
        toAlice.writeObject(beta_bits);
        toAlice.flush();

        // Step C: Alice corrects d...

        // Step D: Alice computes [[alpha XOR beta]]

        // Step E: Alice Computes alpha_hat and w_bits

        // Step F: Alice Exponent w_bits

        // Step G: Alice picks Delta A

        // Step H: Alice computes C_i

        // Step I: Alice blinds C_i

        // Step J: Get C_i and look for zeros
        in = readObject();
        if(in instanceof BigInteger[]) {
            C = (BigInteger []) in;
        }
        else if (in instanceof BigInteger) {
            deltaA = (BigInteger) in;
            return deltaA.intValue() == 1;
        }
        else {
            throw new IllegalArgumentException("Modified Protocol3: invalid input in Step J " + in.getClass().getName());
        }

        for (BigInteger C_i: C) {
            if(DGKOperations.decrypt(C_i, dgk_private) == 0) {
                deltaB = 1;
                break;
            }
        }
        // Run Extra steps to help Alice decrypt Delta
        return decrypt_protocol_one(deltaB);
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
