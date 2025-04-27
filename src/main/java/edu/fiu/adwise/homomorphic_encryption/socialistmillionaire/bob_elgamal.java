package edu.fiu.adwise.homomorphic_encryption.socialistmillionaire;

import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamalCipher;
import edu.fiu.adwise.homomorphic_encryption.elgamal.ElGamal_Ciphertext;
import edu.fiu.adwise.homomorphic_encryption.misc.HomomorphicException;
import edu.fiu.adwise.homomorphic_encryption.misc.NTL;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class bob_elgamal extends bob_veugen {

    private static final Logger logger = LogManager.getLogger(bob_elgamal.class);

    public bob_elgamal(KeyPair a, KeyPair b, KeyPair c) throws IllegalArgumentException {
        super(a, b, c);
    }

    // Support addition and subtraction
    public void addition(boolean addition)
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {
        if (el_gamal_public.additive) {
            throw new HomomorphicException("El Gamal Keys already support addition over cipher-text. " +
                    "Don't outsource it.");
        }

        Object in;
        ElGamal_Ciphertext enc_x_prime;
        ElGamal_Ciphertext enc_y_prime;
        BigInteger x_prime;
        BigInteger y_prime;

        // Step 2
        in = readObject();
        if(in instanceof ElGamal_Ciphertext) {
            enc_x_prime = (ElGamal_Ciphertext) in;
        }
        else {
            throw new IllegalArgumentException("Didn't get [[x']] from Alice: " + in.getClass().getName());
        }

        in = readObject();
        if(in instanceof ElGamal_Ciphertext) {
            enc_y_prime = (ElGamal_Ciphertext) in;
        }
        else {
            throw new IllegalArgumentException("Didn't get [[y']] from Alice: " + in.getClass().getName());
        }

        // Step 3
        x_prime = ElGamalCipher.decrypt(enc_x_prime, el_gamal_private);
        y_prime = ElGamalCipher.decrypt(enc_y_prime, el_gamal_private);
        if(addition) {
            writeObject(ElGamalCipher.encrypt(x_prime.add(y_prime), el_gamal_public));
        }
        else {
            writeObject(ElGamalCipher.encrypt(x_prime.subtract(y_prime), el_gamal_public));
        }
    }

    public void multiplication()
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException
    {
        if (!el_gamal_public.additive) {
            throw new HomomorphicException("El Gamal Keys are not using additive version, so you can't " +
                    "outsource multiply");
        }

        Object in;
        ElGamal_Ciphertext enc_x_prime;
        ElGamal_Ciphertext enc_y_prime;
        BigInteger x_prime;
        BigInteger y_prime;

        // Step 2
        in = readObject();
        if(in instanceof ElGamal_Ciphertext) {
            enc_x_prime = (ElGamal_Ciphertext) in;
        }
        else {
            throw new IllegalArgumentException("Didn't get [[x']] from Alice: " + in.getClass().getName());
        }

        in = readObject();
        if(in instanceof ElGamal_Ciphertext) {
            enc_y_prime = (ElGamal_Ciphertext) in;
        }
        else {
            throw new IllegalArgumentException("Didn't get [[y']] from Alice: " + in.getClass().getName());
        }

        // Step 3
        x_prime = ElGamalCipher.decrypt(enc_x_prime, el_gamal_private);
        y_prime = ElGamalCipher.decrypt(enc_y_prime, el_gamal_private);
        writeObject(ElGamalCipher.encrypt(x_prime.multiply(y_prime), el_gamal_public));
    }

    public void division(long divisor)
            throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException {

        if (!el_gamal_public.additive) {
            throw new HomomorphicException("El Gamal Keys are not using additive version, so you can't " +
                    "outsource division");
        }

        BigInteger c;
        BigInteger z;
        ElGamal_Ciphertext enc_z;
        Object alice = readObject();
        if(alice instanceof ElGamal_Ciphertext) {
            enc_z = (ElGamal_Ciphertext) alice;
        }
        else {
            throw new IllegalArgumentException("Division: No ElGamal Ciphertext found! " + alice.getClass().getName());
        }

        z = ElGamalCipher.decrypt(enc_z, el_gamal_private);
        if(!FAST_DIVIDE) {
            Protocol1(z.mod(BigInteger.valueOf(divisor)));
        }

        c = z.divide(BigInteger.valueOf(divisor));
        writeObject(ElGamalCipher.encrypt(c, el_gamal_public));

        /*
         *  Unlike Comparison, it is decided Bob shouldn't know the answer.
         *  This is because Bob KNOWS d, and can decrypt [x/d]
         *
         *  Since the idea is not leak the numbers themselves,
         *  it is decided Bob shouldn't receive [x/d]
         */
    }


    /**
     * if Alice wants to sort a list of encrypted numbers, use this method if you
     * will consistently sort using Protocol 4
     */
    public void sort()
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {
        long start_time = System.nanoTime();
        int counter = 0;
        while(fromAlice.readBoolean()) {
            ++counter;
            this.Protocol2();
        }
        logger.info("ElGamal Protocol 4 was used " + counter + " times!");
        logger.info("ElGamal Protocol 4 completed in " + (System.nanoTime() - start_time)/BILLION + " seconds!");
    }

    public boolean Protocol2()
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException {

        if (!this.getElGamalPublicKey().additive) {
            throw new HomomorphicException("Encrypted Integer can't work on this version of EL Gamal");
        }

        Object x;
        BigInteger beta;
        BigInteger z;
        ElGamal_Ciphertext enc_z;
        ElGamal_Ciphertext zeta_one;
        ElGamal_Ciphertext zeta_two;
        BigInteger N = el_gamal_public.getP().subtract(BigInteger.ONE);

        //Step 1: get [[z]] from Alice
        x = readObject();
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
        if(readBoolean()) {
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
        writeObject(zeta_one);
        writeObject(zeta_two);

        //Step 6-7: Alice Computes [[x >= y]]
        //Step 8 (UNOFFICIAL): Alice needs the answer...
        return decrypt_protocol_two();
    }

    protected boolean decrypt_protocol_two() throws IOException, ClassNotFoundException {
        Object x;
        int answer;
        x = readObject();
        if (x instanceof ElGamal_Ciphertext) {
            answer = ElGamalCipher.decrypt((ElGamal_Ciphertext) x, el_gamal_private).intValue();
            writeInt(answer);
        }
        else {
            throw new IllegalArgumentException("Protocol 4, Step 8 Failed " + x.getClass().getName());
        }
        // IF SOMETHING HAPPENS...GET TO POST MORTEM HERE
        if (answer != 0 && answer != 1) {
            throw new IllegalArgumentException("Invalid Comparison result --> " + answer);
        }
        return answer == 1;
    }
}
