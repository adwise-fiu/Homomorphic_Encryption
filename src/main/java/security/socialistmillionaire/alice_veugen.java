package security.socialistmillionaire;

import security.dgk.DGKOperations;
import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamal_Ciphertext;
import security.misc.CipherConstants;
import security.misc.HomomorphicException;
import security.misc.NTL;
import security.paillier.PaillierCipher;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class alice_veugen extends alice {
    public alice_veugen(Socket clientSocket) throws IOException {
        super(clientSocket);
    }

    /**
     * Please review the bob
     * @param x - plaintext value
     * @return X <= Y
     */
    public boolean Protocol1(BigInteger x) throws ClassNotFoundException, IOException, HomomorphicException {
        return Protocol3(x, rnd.nextInt(2));
    }

    private boolean Protocol3(BigInteger x, int deltaA)
            throws ClassNotFoundException, IOException, HomomorphicException {
        if(x.bitLength() > dgk_public.getL()) {
            throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + x.bitLength() + " bits");
        }

        Object in;
        BigInteger [] XOR;
        BigInteger [] C;
        BigInteger [] Encrypted_Y;
        int deltaB;
        int answer;

        //Step 1: Receive y_i bits from Bob
        in = fromBob.readObject();
        if (in instanceof BigInteger[]) {
            Encrypted_Y = (BigInteger []) in;
        }
        else {
            System.err.println("Invalid Object received: " + in.getClass().getName());
            throw new IllegalArgumentException("Protocol 3 Step 1: Missing Y-bits!");
        }

        /*
         * Currently by design of the program
         * 1- Alice KNOWS that bob will assume deltaB = 0.
         *
         * Alice knows the protocol should be paillier_private if
         * the bit length is NOT equal.
         *
         * Case 1:
         * y has more bits than x IMPLIES that y is bigger
         * x <= y is 1 (true)
         * given deltaB is 0 by default...
         * deltaA must be 1
         * answer = 1 XOR 0 = 1
         *
         * Case 2:
         * x has more bits than x IMPLIES that x is bigger
         * x <= y is 0 (false)
         * given deltaB is 0 by default...
         * deltaA must be 0
         * answer = 0 XOR 0 = 0
         */

        // Case 1, delta B is ALWAYS INITIALIZED TO 0
        // y has more bits -> y is bigger
        if (x.bitLength() < Encrypted_Y.length) {
            toBob.writeObject(BigInteger.ONE);
            toBob.flush();
            // x <= y -> 1 (true)
            return true;
        }

        // Case 2 delta B is 0
        // x has more bits -> x is bigger
        else if(x.bitLength() > Encrypted_Y.length) {
            toBob.writeObject(BigInteger.ZERO);
            toBob.flush();
            // x <= y -> 0 (false)
            return false;
        }

        // if equal bits, proceed!
        // Step 2: compute Encrypted X XOR Y
        XOR = new BigInteger[Encrypted_Y.length];
        for (int i = 0; i < Encrypted_Y.length; i++) {
            if (NTL.bit(x, i) == 1) {
                XOR[i] = DGKOperations.subtract(dgk_public.ONE(), Encrypted_Y[i], dgk_public);
            }
            else {
                XOR[i] = Encrypted_Y[i];
            }
        }

        // Step 3: delta A is computed on initialization, it is 0 or 1.

        // Step 4A: Generate C_i, see c_{-1} to test for equality!
        // Step 4B: alter C_i using Delta A
        // C_{-1} = C_i[yBits], will be computed at the end...
        C = new BigInteger [Encrypted_Y.length + 1];

        for (int i = 0; i < Encrypted_Y.length; i++) {
            C[i] = DGKOperations.sum(XOR, dgk_public, Encrypted_Y.length - 1 - i);
            if (deltaA == 0) {
                // Step 4 = [1] - [y_i bit] + [c_i]
                // Step 4 = [c_i] - [y_i bit] + [1]
                C[i] = DGKOperations.subtract(C[i], Encrypted_Y[Encrypted_Y.length - 1 - i], dgk_public);
                C[i] = DGKOperations.add_plaintext(C[i], 1, dgk_public);
            }
            else {
                // Step 4 = [y_i] + [c_i]
                C[i]= DGKOperations.add(C[i], Encrypted_Y[Encrypted_Y.length - 1 - i], dgk_public);
            }
        }

        // This is c_{-1}
        C[Encrypted_Y.length] = DGKOperations.sum(XOR, dgk_public);
        C[Encrypted_Y.length] = DGKOperations.add_plaintext(C[Encrypted_Y.length], deltaA, dgk_public);

        // Step 5: Apply the Blinding to C_i and send it to Bob
        for (int i = 0; i < Encrypted_Y.length; i++) {
            // if index i is NOT in L, just place a random NON-ZERO
            // int bit = x.testBit(i) ? 1 : 0;
            int bit = NTL.bit(x, i);
            if(bit != deltaA) {
                C[Encrypted_Y.length - 1 - i] = DGKOperations.encrypt(rnd.nextInt(dgk_public.getL()) + 1, dgk_public);
            }
        }
        // Blind and Shuffle bits!
        C = shuffle_bits(C);
        for (int i = 0; i < C.length; i++) {
            C[i] = DGKOperations.multiply(C[i], rnd.nextInt(dgk_public.getL()) + 1, dgk_public);
        }
        toBob.writeObject(C);
        toBob.flush();

        // Step 7: Obtain Delta B from Bob
        deltaB = fromBob.readInt();

        // 1 XOR 1 = 0 and 0 XOR 0 = 0, so X > Y
        if (deltaA == deltaB) {
            answer = 0;
        }
        // 1 XOR 0 = 1 and 0 XOR 1 = 1, so X <= Y
        else {
            answer = 1;
        }

        /*
         * Step 8: Bob has the Private key anyway...
         * Send him the encrypted answer!
         * Alice and Bob know now without revealing x or y!
         */
        toBob.writeObject(DGKOperations.encrypt(BigInteger.valueOf(answer), dgk_public));
        toBob.flush();
        return answer == 1;
    }


    /**
     * Primarily used in Protocol 4.
     */
    public boolean Modified_Protocol3(BigInteger r)
            throws ClassNotFoundException, IOException, HomomorphicException
    {
        BigInteger alpha;
        boolean answer;
        // Constraint...
        if(r.bitLength() > dgk_public.getL()) {
            throw new IllegalArgumentException("Constraint violated: 0 <= x, y < 2^l, x is: " + r.bitLength() + " bits");
        }
        if(isDGK) {
            alpha = r.mod(powL);
            answer = Modified_Protocol3(alpha, r, rnd.nextInt(2));
        }
        else {
            isDGK = true;
            alpha = r.mod(powL);
            answer = Modified_Protocol3(alpha, r, rnd.nextInt(2));
            isDGK = false;
        }
        return answer;
    }

    private boolean Modified_Protocol3(BigInteger alpha, BigInteger r, int deltaA)
            throws ClassNotFoundException, IOException, HomomorphicException
    {
        int answer;
        Object in;
        BigInteger [] beta_bits;
        BigInteger [] encAlphaXORBeta;
        BigInteger [] w;
        BigInteger [] C;
        BigInteger alpha_hat;
        BigInteger d;
        BigInteger N;
        long exponent;

        // Get N from size of Plain-text space
        if(this.isDGK) {
            N = dgk_public.getU();
        }
        else {
            N = paillier_public.getN();
        }

        // Step A: get d from Bob
        in = fromBob.readObject();
        if (in instanceof BigInteger) {
            d = (BigInteger) in;
        }
        else {
            System.err.println("Invalid Object received: " + in.getClass().getName());
            throw new IllegalArgumentException("BigInteger: d not found!");
        }

        // Step B: get beta_bits from Bob
        in = fromBob.readObject();
        if (in instanceof BigInteger[]) {
            beta_bits = (BigInteger []) in;
        }
        else {
            System.err.println("Invalid Object received: " + in.getClass().getName());
            throw new IllegalArgumentException("BigInteger []: C not found!");
        }

        /*
         * Currently by design of the program
         * 1- Alice KNOWS that bob will assume deltaB = 0.
         *
         * Alice knows the protocol should be paillier_private if
         * the bit length is NOT equal.
         *
         * Case 1:
         * y has more bits than x IMPLIES that y is bigger
         * x <= y is 1 (true)
         * given deltaB is 0 by default...
         * deltaA must be 1
         * answer = 1 XOR 0 = 1
         *
         * Case 2:
         * x has more bits than x IMPLIES that x is bigger
         * x <= y is 0 (false)
         * given deltaB is 0 by default...
         * deltaA must be 0
         * answer = 0 XOR 0 = 0
         */

        if (alpha.bitLength() < beta_bits.length) {
            toBob.writeObject(BigInteger.ONE);
            toBob.flush();
            return true;
        }
        else if(alpha.bitLength() > beta_bits.length) {
            toBob.writeObject(BigInteger.ZERO);
            toBob.flush();
            return false;
        }

        // Step C: Alice corrects d...
        if(r.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) < 0) {
            d = DGKOperations.encrypt(BigInteger.ZERO, dgk_public);
        }

        // Step D: Compute alpha_bits XOR beta_bits
        encAlphaXORBeta = new BigInteger[beta_bits.length];
        for (int i = 0; i < encAlphaXORBeta.length; i++) {
            if (NTL.bit(alpha, i) == 1) {
                encAlphaXORBeta[i] = DGKOperations.subtract(dgk_public.ONE(), beta_bits[i], dgk_public);
            }
            else {
                encAlphaXORBeta[i] = beta_bits[i];
            }
        }

        // Step E: Compute Alpha Hat
        alpha_hat = r.subtract(N).mod(powL);
        w = new BigInteger[beta_bits.length];

        for (int i = 0; i < beta_bits.length;i++) {
            if(NTL.bit(alpha_hat, i) == NTL.bit(alpha, i)) {
                w[i] = encAlphaXORBeta[i];
            }
            else {
                w[i] = DGKOperations.subtract(encAlphaXORBeta[i], d, dgk_public);
            }
        }

        // Step F: See Optimization 1
        for (int i = 0; i < beta_bits.length;i++) {
            // If it is 16 or 32 bits...
            if(dgk_public.getL() % 16 == 0) {
                if(NTL.bit(alpha_hat, i) != NTL.bit(alpha, i)) {
                    w[i] = DGKOperations.multiply(w[i], dgk_public.getL(), dgk_public);
                }
            }
            else {
                BigInteger exponent_i = TWO.pow(i);
                w[i] = DGKOperations.multiply(w[i], exponent_i, dgk_public);
            }
        }

        // Step G: Delta A computed at start!

        // Step H: See Optimization 2
        C = new BigInteger[beta_bits.length + 1];

        for (int i = 0; i < beta_bits.length;i++) {
            if(deltaA != NTL.bit(alpha, i) && deltaA != NTL.bit(alpha_hat, i)) {
                C[i] = dgk_public.ONE();
            }
            else {
                exponent = 0;
                if(alpha_hat.testBit(i)) {
                    exponent += 1;
                }
                if(alpha.testBit(i)) {
                    exponent -= 1;
                }
                exponent = NTL.bit(alpha_hat, i) - NTL.bit(alpha, i);
                C[i] = DGKOperations.multiply(DGKOperations.sum(w, dgk_public, i), 3, dgk_public);
                C[i] = DGKOperations.add_plaintext(C[i], 1 - (2L * deltaA), dgk_public);
                C[i] = DGKOperations.add(C[i], DGKOperations.multiply(d, exponent, dgk_public), dgk_public);
                C[i] = DGKOperations.subtract(C[i], beta_bits[i], dgk_public);
                C[i] = DGKOperations.add_plaintext(C[i], NTL.bit(alpha, i), dgk_public);
            }
        }

        //This is c_{-1}
        C[beta_bits.length] = DGKOperations.sum(encAlphaXORBeta, dgk_public);
        C[beta_bits.length] = DGKOperations.add_plaintext(C[beta_bits.length], deltaA, dgk_public);

        // Step I: SHUFFLE BITS AND BLIND WITH EXPONENT
        C = shuffle_bits(C);
        for (int i = 0; i < C.length; i++) {
            C[i] = DGKOperations.multiply(C[i], rnd.nextInt(dgk_public.getU().intValue()) + 1, dgk_public);
        }
        toBob.writeObject(C);
        toBob.flush();

        // Step J: Bob checks whether a C_i has a zero or not...get delta B.
        int deltaB = fromBob.readInt();
        if (deltaA == deltaB) {
            answer = 0;
        }
        else {
            answer = 1;
        }
        toBob.writeObject(DGKOperations.encrypt(answer, dgk_public));
        toBob.flush();
        return answer == 1;
    }

    /**
     *
     * @param x - Encrypted Paillier value OR Encrypted DGK value
     * @param y - Encrypted Paillier value OR Encrypted DGK value
     * @throws IOException - socket errors
     */
    public boolean Protocol2(BigInteger x, BigInteger y)
            throws IOException, ClassNotFoundException, HomomorphicException {
        int deltaB;
        int x_leq_y;
        int comparison;
        int deltaA = rnd.nextInt(2);
        Object bob;
        BigInteger alpha_lt_beta;
        BigInteger z;
        BigInteger zeta_one;
        BigInteger zeta_two;
        BigInteger result;
        BigInteger r;
        BigInteger alpha;
        BigInteger N;

        /*
         * Step 1: 0 <= r < N
         * N is the Paillier plain text space, which is 1024-bits usually
         * u is the DGK plain text space, which is l bits
         *
         * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
         * Send Z to Bob
         * [[x + 2^l + r]]
         * [[z]] = [[x - y + 2^l + r]]
         */
        if (isDGK) {
            r = NTL.RandomBnd(dgk_public.getU());
            z = DGKOperations.add_plaintext(x, r.add(powL).mod(dgk_public.getU()), dgk_public);
            z = DGKOperations.subtract(z, y, dgk_public);
            N = dgk_public.getU();
        }
        else {
            r = NTL.RandomBnd(paillier_public.getN());
            z = PaillierCipher.add_plaintext(x, r.add(powL).mod(paillier_public.getN()), paillier_public);
            z = PaillierCipher.subtract(z, y, paillier_public);
            N = paillier_public.getN();
        }
        toBob.writeObject(z);
        toBob.flush();

        // Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

        // Step 3: alpha = r (mod 2^l)
        alpha = NTL.POSMOD(r, powL);

        // Step 4: Modified Protocol 3 or Protocol 3

        // See Optimization 3: true --> Use Modified Protocol 3
        if(r.add(TWO.pow(dgk_public.getL() + 1)).compareTo(N) < 0) {
            toBob.writeBoolean(false);
            toBob.flush();
            if(Protocol3(alpha, deltaA)) {
                x_leq_y = 1;
            }
            else {
                x_leq_y = 0;
            }
        }
        else
        {
            toBob.writeBoolean(true);
            toBob.flush();
            if(Modified_Protocol3(alpha, r, deltaA)) {
                x_leq_y = 1;
            }
            else {
                x_leq_y = 0;
            }
        }

        // Step 5: get Delta B and [[z_1]] and [[z_2]]
        if(deltaA == x_leq_y) {
            deltaB = 0;
        }
        else {
            deltaB = 1;
        }

        bob = fromBob.readObject();
        if (bob instanceof BigInteger) {
            zeta_one = (BigInteger) bob;
        }
        else {
            throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_1 not found, Invalid object: " +  bob.getClass().getName());
        }

        bob = fromBob.readObject();
        if (bob instanceof BigInteger) {
            zeta_two = (BigInteger) bob;
        }
        else {
            throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_2 not found, Invalid object: " + bob.getClass().getName());
        }

        // Step 6: Compute [[beta <= alpha]]
        if(isDGK) {
            if(deltaA == 1) {
                alpha_lt_beta = DGKOperations.encrypt(deltaB, dgk_public);
            }
            else {
                alpha_lt_beta = DGKOperations.encrypt(1 - deltaB, dgk_public);
            }

            // Step 7: Compute [[x > y]]
            if(r.compareTo(dgk_public.getU().subtract(BigInteger.ONE).divide(TWO)) < 0) {
                result = DGKOperations.subtract(zeta_one, DGKOperations.encrypt(r.divide(powL), dgk_public), dgk_public);
            }
            else {
                result = DGKOperations.subtract(zeta_two, DGKOperations.encrypt(r.divide(powL), dgk_public), dgk_public);
            }
            result = DGKOperations.subtract(result, alpha_lt_beta, dgk_public);
        }
        else
        {
            if(deltaA == 1) {
                alpha_lt_beta = PaillierCipher.encrypt(deltaB, paillier_public);
            }
            else {
                alpha_lt_beta = PaillierCipher.encrypt(1 - deltaB, paillier_public);
            }

            // Step 7: Compute [[x >= y]]
            if(r.compareTo(paillier_public.getN().subtract(BigInteger.ONE).divide(TWO)) < 0) {
                result = PaillierCipher.subtract(zeta_one, PaillierCipher.encrypt(r.divide(powL), paillier_public), paillier_public);
            }
            else {
                result = PaillierCipher.subtract(zeta_two, PaillierCipher.encrypt(r.divide(powL), paillier_public), paillier_public);
            }
            result = PaillierCipher.subtract(result, alpha_lt_beta, paillier_public);
        }

        /*
         * Unofficial Step 8:
         * Since the result is encrypted...I need to send
         * this back to Bob (Android Phone) to decrypt the solution...
         *
         * Bob by definition would know the answer as well.
         */

        toBob.writeObject(result);
        comparison = fromBob.readInt();// x <= y
        // IF SOMETHING HAPPENS...GET POST MORTEM HERE
        if (comparison != 0 && comparison != 1) {
            throw new IllegalArgumentException("Invalid Comparison result --> " + comparison);
        }
        return comparison == 1;
    }

    public boolean Protocol4(ElGamal_Ciphertext x, ElGamal_Ciphertext y)
            throws IOException, ClassNotFoundException, HomomorphicException
    {
        int deltaB;
        int x_leq_y;
        int comparison;
        int deltaA = rnd.nextInt(2);
        Object bob;
        ElGamal_Ciphertext alpha_lt_beta;
        ElGamal_Ciphertext z;
        ElGamal_Ciphertext zeta_one;
        ElGamal_Ciphertext zeta_two;
        ElGamal_Ciphertext result;
        BigInteger r;
        BigInteger alpha;
        BigInteger N = el_gamal_public.getP().subtract(BigInteger.ONE);

        // Step 1: 0 <= r < N
        r = NTL.RandomBnd(CipherConstants.FIELD_SIZE);

        /*
         * Step 2: Alice computes [[z]] = [[x - y + 2^l + r]]
         * Send Z to Bob
         * [[x + 2^l + r]]
         * [[z]] = [[x - y + 2^l + r]]
         */
        z = ElGamalCipher.add(x, ElGamalCipher.encrypt(r.add(powL), el_gamal_public), el_gamal_public);
        z = ElGamalCipher.subtract(z, y, el_gamal_public);
        toBob.writeObject(z);
        toBob.flush();

        // Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

        // Step 3: alpha = r (mod 2^l)
        alpha = NTL.POSMOD(r, powL);

        // Step 4: Modified Protocol 3 or Protocol 3

        // See Optimization 3: true --> Use Modified Protocol 3
        if(r.add(TWO.pow(dgk_public.getL() + 1)).compareTo(N) < 0) {
            toBob.writeBoolean(false);
            toBob.flush();
            if(Protocol3(alpha, deltaA)) {
                x_leq_y = 1;
            }
            else {
                x_leq_y = 0;
            }
        }
        else {
            toBob.writeBoolean(true);
            toBob.flush();
            if(Modified_Protocol3(alpha, r, deltaA)) {
                x_leq_y = 1;
            }
            else {
                x_leq_y = 0;
            }
        }

        // Step 5: get Delta B and [[z_1]] and [[z_2]]
        if(deltaA == x_leq_y) {
            deltaB = 0;
        }
        else {
            deltaB = 1;
        }

        bob = fromBob.readObject();
        if (bob instanceof ElGamal_Ciphertext) {
            zeta_one = (ElGamal_Ciphertext) bob;
        }
        else {
            System.err.println("Invalid Object received: " + bob.getClass().getName());
            throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_1 not found!");
        }

        bob = fromBob.readObject();
        if (bob instanceof ElGamal_Ciphertext) {
            zeta_two = (ElGamal_Ciphertext) bob;
        }
        else {
            System.err.println("Invalid Object received: " + bob.getClass().getName());
            throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_2 not found!");
        }

        // Step 6: Compute [[beta <= alpha]]
        if(deltaA == 1) {
            alpha_lt_beta = ElGamalCipher.encrypt(deltaB, el_gamal_public);
        }
        else {
            alpha_lt_beta = ElGamalCipher.encrypt(1 - deltaB, el_gamal_public);
        }

        // Step 7: Compute [[x <= y]]
        if(r.compareTo(N.subtract(BigInteger.ONE).divide(TWO)) < 0) {
            result = ElGamalCipher.subtract(zeta_one, ElGamalCipher.encrypt(r.divide(powL), el_gamal_public), el_gamal_public);
        }
        else {
            result = ElGamalCipher.subtract(zeta_two, ElGamalCipher.encrypt(r.divide(powL), el_gamal_public), el_gamal_public);
        }
        result = ElGamalCipher.subtract(result, alpha_lt_beta, el_gamal_public);

        /*
         * Unofficial Step 8:
         * Since the result is encrypted...I need to send
         * this back to Bob (Android Phone) to decrypt the solution...
         *
         * Bob by definition would know the answer as well.
         */

        toBob.writeObject(result);
        toBob.flush();
        comparison = fromBob.readInt();
        // IF SOMETHING HAPPENS...GET POST MORTEM HERE
        if (comparison != 0 && comparison != 1) {
            throw new IllegalArgumentException("Invalid Comparison result --> " + comparison);
        }
        return comparison == 1;
    }

    public void getKMin_ElGamal(List<ElGamal_Ciphertext> input, int k)
            throws ClassNotFoundException, IOException, IllegalArgumentException, HomomorphicException
    {
        if(k > input.size() || k <= 0) {
            throw new IllegalArgumentException("Invalid k value! " + k);
        }
        // deep copy
        List<ElGamal_Ciphertext> arr = new ArrayList<>(input);

        ElGamal_Ciphertext temp;
        List<ElGamal_Ciphertext> min = new ArrayList<>();

        for (int i = 0; i < k; i++) {
            for (int j = 0; j < arr.size() - i - 1; j++) {
                toBob.writeBoolean(true);
                toBob.flush();

                // Originally arr[j] > arr[j + 1]
                if (!this.Protocol4(arr.get(j), arr.get(j + 1))) {
                    // swap temp and arr[i]
                    temp = arr.get(j);
                    arr.set(j, arr.get(j + 1));
                    arr.set(j + 1, temp);
                }
            }
        }

        // Get last K-elements of arr!!
        for (int i = 0; i < k; i++) {
            min.add(arr.get(arr.size() - 1 - i));
        }

        // Close Bob
        toBob.writeBoolean(false);
        toBob.flush();
    }
}
