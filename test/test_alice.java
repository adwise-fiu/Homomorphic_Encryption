package test;

import security.misc.HomomorphicException;
import security.paillier.PaillierCipher;
import security.paillier.PaillierPublicKey;
import security.socialistmillionaire.*;

import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;


public class test_alice {

    public static void main(String[] args) 
    		throws HomomorphicException, IOException, ClassNotFoundException 
    {
        long num1=127;
        long num2=64;

        // Connect to Bob
        alice Niu = new alice(new Socket("127.0.0.1", 9254));
        
        // Since Bob built the key pair, and automatically hands you the public key
        // get it now from bob (bob hands it to Alice in constructor)
        PaillierPublicKey pka = Niu.getPaillierPublicKey();
        
        // create and encrypt numbers
        BigInteger firstNumber = BigInteger.valueOf(num1);
        BigInteger secondNumber = BigInteger.valueOf(num2);
        BigInteger firstNumberEncrypted = PaillierCipher.encrypt(firstNumber, pka);
        BigInteger secondNumberEncrypted = PaillierCipher.encrypt(secondNumber, pka);

        boolean firstGreaterThanSecond = Niu.Protocol4(firstNumberEncrypted, secondNumberEncrypted);
        System.out.println(firstGreaterThanSecond);
    }
}