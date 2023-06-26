package security.socialistmillionaire;

import security.dgk.DGKOperations;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamal_Ciphertext;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;

public class bob_veugen extends bob {

    public bob_veugen(KeyPair a, KeyPair b, KeyPair c) throws IllegalArgumentException {
        super(a, b, c);
    }

    public bob_veugen(Socket clientSocket, KeyPair a, KeyPair b, KeyPair c) throws IOException, IllegalArgumentException {
        super(clientSocket, a, b, c);
    }

    // Use this for Using Modified Protocol3 within Protocol 4
    private boolean Modified_Protocol3(BigInteger beta, BigInteger z)
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {
        Object in;
        BigInteger [] C;
        BigInteger [] beta_bits = new BigInteger[beta.bitLength()];
        BigInteger deltaA;
        BigInteger d;
        BigInteger N;
        int answer;
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
        in = fromAlice.readObject();
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
        toAlice.writeInt(deltaB);
        toAlice.flush();

        // Extra step...Bob gets the answer from Alice
        in = fromAlice.readObject();
        if(in instanceof BigInteger) {
            answer = (int) DGKOperations.decrypt((BigInteger) in, dgk_private);
        }
        else {
            throw new IllegalArgumentException("Modified_Protocol 3, Step 8 Invalid Object! " + in.getClass().getName());
        }
        toAlice.flush();
        return answer == 1;
    }

    /**
     * Please review Correction to Improving the DGK comparison protocol - Protocol 3
     */
    public boolean Protocol2()
            throws IOException, ClassNotFoundException, HomomorphicException
    {
        // Constraint for Paillier
        if(!isDGK && dgk_public.getL() + 2 >= paillier_public.key_size) {
            throw new IllegalArgumentException("Constraint violated: l + 2 < log_2(N)");
        }

        int answer = -1;
        Object x;
        BigInteger beta;
        BigInteger z;
        BigInteger zeta_one;
        BigInteger zeta_two;

        //Step 1: get [[z]] from Alice
        x = fromAlice.readObject();
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

        if(fromAlice.readBoolean()) {
            if(Modified_Protocol3(beta, z)) {
                System.out.println("Modified Protocol 3 selected");
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
        x = fromAlice.readObject();
        if (x instanceof BigInteger) {
            if(isDGK) {
                long decrypt = DGKOperations.decrypt((BigInteger) x, dgk_private);
                // IF SOMETHING HAPPENS...GET POST MORTEM HERE
                if (decrypt != 0 && dgk_public.getU().longValue() - 1 != decrypt) {
                    throw new IllegalArgumentException("Invalid Comparison result --> " + answer);
                }

                if (dgk_public.getu() - 1 == decrypt) {
                    answer = 0;
                }
                else {
                    answer = 1;
                }
            }
            else {
                answer = PaillierCipher.decrypt((BigInteger) x, paillier_private).intValue();
            }
            toAlice.writeInt(answer);
            toAlice.flush();
        }
        else {
            throw new IllegalArgumentException("Protocol 4, Step 8 Failed " + x.getClass().getName());
        }
        // IF SOMETHING HAPPENS...GET POST MORTEM HERE
        if (answer != 0 && answer != 1) {
            throw new IllegalArgumentException("Invalid Comparison result --> " + answer);
        }
        return answer == 1;
    }


    /**
     * if Alice wants to sort a list of encrypted numbers, use this method if you
     * will consistently sort using Protocol 4
     */
    public void repeat_ElGamal_Protocol4()
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {
        long start_time = System.nanoTime();
        int counter = 0;
        while(fromAlice.readBoolean()) {
            ++counter;
            this.ElGamal_Protocol4();
        }
        System.out.println("ElGamal Protocol 4 was used " + counter + " times!");
        System.out.println("ElGamal Protocol 4 completed in " + (System.nanoTime() - start_time)/BILLION + " seconds!");
    }

    public void ElGamal_Protocol4()
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {

        if (!this.getElGamalPublicKey().additive) {
            throw new HomomorphicException("Encrypted Integer can't work on this version of EL Gamal");
        }

        int answer;
        Object x;
        BigInteger beta;
        BigInteger z;
        ElGamal_Ciphertext enc_z;
        ElGamal_Ciphertext zeta_one;
        ElGamal_Ciphertext zeta_two;
        BigInteger N = el_gamal_public.getP().subtract(BigInteger.ONE);

        //Step 1: get [[z]] from Alice
        x = fromAlice.readObject();
        if (x instanceof ElGamal_Ciphertext) {
            enc_z = (ElGamal_Ciphertext) x;
        }
        else {
            throw new IllegalArgumentException("Protocol 4: No ElGamal_Ciphertext found! " + x.getClass().getName());
        }
        z = ElGamalCipher.decrypt(enc_z, el_gamal_private);

        // Step 2: compute Beta = z (mod 2^l),
        beta = NTL.POSMOD(z, powL);

        // Step 3: Alice computes r (mod 2^l) (Alpha)

        // Step 4: Run Modified DGK Comparison Protocol
        // true --> run Modified protocol 3
        if(fromAlice.readBoolean()) {
            Modified_Protocol3(beta, z);
        }
        else {
            Protocol1(beta);
        }

        //Step 5" Send [[z/2^l]], Alice has the solution from Protocol 3 already
        zeta_one = ElGamalCipher.encrypt(z.divide(powL), el_gamal_public);
        if(z.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) < 0) {
            zeta_two = ElGamalCipher.encrypt(z.add(N).divide(powL), el_gamal_public);
        }
        else {
            zeta_two = ElGamalCipher.encrypt(z.divide(powL), el_gamal_public);
        }
        toAlice.writeObject(zeta_one);
        toAlice.writeObject(zeta_two);
        toAlice.flush();

        //Step 6 - 7: Alice Computes [[x >= y]]
        //Step 8 (UNOFFICIAL): Alice needs the answer...
        x = fromAlice.readObject();
        if (x instanceof ElGamal_Ciphertext) {
            answer = ElGamalCipher.decrypt((ElGamal_Ciphertext) x, el_gamal_private).intValue();
            toAlice.writeInt(answer);
            toAlice.flush();
        }
        else {
            throw new IllegalArgumentException("Protocol 4, Step 8 Failed " + x.getClass().getName());
        }
        // IF SOMETHING HAPPENS...GET POST MORTEM HERE
        if (answer != 0 && answer != 1) {
            throw new IllegalArgumentException("Invalid Comparison result --> " + answer);
        }
    }
}
