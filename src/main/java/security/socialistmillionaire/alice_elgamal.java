package security.socialistmillionaire;

import security.elgamal.ElGamalCipher;
import security.elgamal.ElGamal_Ciphertext;
import security.misc.CipherConstants;
import security.misc.HomomorphicException;
import security.misc.NTL;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class alice_elgamal extends alice_veugen {
    private static final Logger logger = LogManager.getLogger(alice_elgamal.class);

    public alice_elgamal() {
        super();
    }

    public ElGamal_Ciphertext addition(ElGamal_Ciphertext x, ElGamal_Ciphertext y)
            throws IOException, ClassNotFoundException, IllegalArgumentException
    {
        if(el_gamal_public.additive) {
            // Can add both ciphertexts by default
            return ElGamalCipher.add(x, y, el_gamal_public);
        }
        // Must outsource this operation
        Object in;
        ElGamal_Ciphertext x_prime;
        ElGamal_Ciphertext y_prime;
        BigInteger plain_a = NTL.RandomBnd(dgk_public.getU());
        ElGamal_Ciphertext a = ElGamalCipher.encrypt(plain_a, el_gamal_public);
        ElGamal_Ciphertext result;

        // Step 1
        x_prime = ElGamalCipher.multiply(x, a, el_gamal_public);
        y_prime = ElGamalCipher.multiply(y, a, el_gamal_public);

        writeObject(x_prime);
        writeObject(y_prime);

        // Step 2

        // Step 3
        in = readObject();
        if (in instanceof ElGamal_Ciphertext) {
            result = (ElGamal_Ciphertext) in;
            result = ElGamalCipher.divide(result, a ,el_gamal_public);
        }
        else {
            throw new IllegalArgumentException("Didn't get [[x' * y']] from Bob: " + in.getClass().getName());
        }
        return result;
    }

    public ElGamal_Ciphertext multiplication(ElGamal_Ciphertext x, ElGamal_Ciphertext y)
            throws IOException, ClassNotFoundException, IllegalArgumentException
    {
        if(!el_gamal_public.additive) {
            return ElGamalCipher.multiply(x, y, el_gamal_public);
        }
        Object in;
        ElGamal_Ciphertext result;
        ElGamal_Ciphertext x_prime;
        ElGamal_Ciphertext y_prime;
        BigInteger a;
        BigInteger b;
        BigInteger N = CipherConstants.FIELD_SIZE;

        // Step 1
        a = NTL.RandomBnd(N);
        b = NTL.RandomBnd(N);
        x_prime = ElGamalCipher.add(x, ElGamalCipher.encrypt(a, el_gamal_public), el_gamal_public);
        y_prime = ElGamalCipher.add(y, ElGamalCipher.encrypt(b, el_gamal_public), el_gamal_public);

        writeObject(x_prime);
        writeObject(y_prime);

        // Step 2

        // Step 3
        in = readObject();
        if (in instanceof ElGamal_Ciphertext) {
            result = (ElGamal_Ciphertext) in;
            result = ElGamalCipher.subtract(result, ElGamalCipher.multiply_scalar(x, b, el_gamal_public), el_gamal_public);
            result = ElGamalCipher.subtract(result, ElGamalCipher.multiply_scalar(y, a, el_gamal_public), el_gamal_public);
            result = ElGamalCipher.subtract(result, ElGamalCipher.encrypt(a.multiply(b), el_gamal_public), el_gamal_public);
        }
        else {
            throw new IllegalArgumentException("Didn't get [[x' * y']] from Bob: " + in.getClass().getName());
        }
        return result;
    }

    public ElGamal_Ciphertext division(ElGamal_Ciphertext x, long d)
            throws IOException, ClassNotFoundException, IllegalArgumentException, HomomorphicException
    {
        if(!el_gamal_public.additive) {
            ElGamalCipher.divide(x, ElGamalCipher.encrypt(BigInteger.valueOf(d), el_gamal_public), el_gamal_public);
            return x;
        }
        Object in;
        ElGamal_Ciphertext answer;
        ElGamal_Ciphertext c;
        ElGamal_Ciphertext z;
        BigInteger r;
        int t = 0;

        // Step 1
        r = NTL.generateXBitRandom(16 - 1);
        z = ElGamalCipher.add(x, ElGamalCipher.encrypt(r, el_gamal_public), el_gamal_public);
        writeObject(z);

        // Step 2: Executed by Bob

        // Step 3: Compute secure comparison Protocol
        if(!FAST_DIVIDE) {
            // FLIP IT
            if(!Protocol1(r.mod(BigInteger.valueOf(d)))) {
                t = 1;
            }
        }

        // Step 4: Bob computes c and Alice receives it
        in = readObject();
        if (in instanceof ElGamal_Ciphertext) {
            c = (ElGamal_Ciphertext) in;
        }
        else {
            throw new IllegalArgumentException("Alice: ElGamal Ciphertext not found! " + in.getClass().getName());
        }

        // Step 5: Alice computes [x/d]
        // [[z/d - r/d]]
        // [[z/d - r/d - t]]
        answer = ElGamalCipher.subtract(c, ElGamalCipher.encrypt(r.divide(BigInteger.valueOf(d)), el_gamal_public), el_gamal_public);
        if(t == 1) {
            answer = ElGamalCipher.subtract(answer, ElGamalCipher.encrypt(t, el_gamal_public), el_gamal_public);
        }
        return answer;
    }

    public boolean Protocol4(ElGamal_Ciphertext x, ElGamal_Ciphertext y)
            throws IOException, ClassNotFoundException, HomomorphicException
    {
        int deltaB;
        int x_leq_y;
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
        writeObject(z);

        // Step 2: Bob decrypts[[z]] and computes beta = z (mod 2^l)

        // Step 3: alpha = r (mod 2^l)
        alpha = NTL.POSMOD(r, powL);

        // Step 4: Modified Protocol 3 or Protocol 3

        // See Optimization 3: true --> Use Modified Protocol 3
        if(r.add(TWO.pow(dgk_public.getL() + 1)).compareTo(N) < 0) {
            writeBoolean(false);

            if(Protocol3(alpha, deltaA)) {
                x_leq_y = 1;
            }
            else {
                x_leq_y = 0;
            }
        }
        else {
            writeBoolean(true);

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

        bob = readObject();
        if (bob instanceof ElGamal_Ciphertext) {
            zeta_one = (ElGamal_Ciphertext) bob;
        }
        else {
            logger.error("Invalid Object received: " + bob.getClass().getName());
            throw new IllegalArgumentException("Protocol 4, Step 5: BigInteger z_1 not found!");
        }

        bob = readObject();
        if (bob instanceof ElGamal_Ciphertext) {
            zeta_two = (ElGamal_Ciphertext) bob;
        }
        else {
            logger.error("Invalid Object received: " + bob.getClass().getName());
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
        return decrypt_protocol_two(result);
    }

    protected boolean decrypt_protocol_two(ElGamal_Ciphertext result) throws IOException {
        int comparison;
        writeObject(result);

        comparison = fromBob.readInt();
        // IF SOMETHING HAPPENS...GET THE POST MORTEM HERE
        if (comparison != 0 && comparison != 1) {
            throw new IllegalArgumentException("Invalid Comparison result --> " + comparison);
        }
        return comparison == 1;
    }

    public List<ElGamal_Ciphertext> getKMin(List<ElGamal_Ciphertext> input, int k)
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
                writeBoolean(true);

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
        writeBoolean(false);
        return min;
    }
}
