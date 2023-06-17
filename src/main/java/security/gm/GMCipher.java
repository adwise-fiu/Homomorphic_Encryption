package security.gm;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import security.misc.CipherConstants;
import security.misc.HomomorphicException;
import security.misc.NTL;

public class GMCipher implements CipherConstants
{
	//------------------------------------------Original BigInteger Code----------------------------------------
	
	/**
	 * Encrypt a BigInteger plaintext using Goldwasser-Micali
	 * @param message - plaintext message
	 * @param public_key - used to encrypt plaintext
	 * @return - Goldwasser-Micali encrypted bits
	 */
	public static BigInteger [] encrypt(BigInteger message, GMPublicKey public_key) {
		List<BigInteger> enc_bits = new ArrayList<>();
		BigInteger x;
		for(int i = message.bitLength() - 1; i >= 0 ; i--) {
			x = NTL.RandomBnd(public_key.n);
			if(message.testBit(i)) {
				enc_bits.add(public_key.y.multiply(x.modPow(TWO, public_key.n)).mod(public_key.n));
			}
			else {
				enc_bits.add(x.modPow(TWO, public_key.n));
			}
		}
		Collections.reverse(enc_bits);
		return enc_bits.toArray(new BigInteger[0]);
	}

	/**
	 * Decrypt Goldwasser-Micali encrypted bits
	 * @param cipher - List of Goldwasser-Micali encrypted bits
	 * @param private_key - Goldwasser-Micali Private Key to decrypt
	 */
	public static BigInteger decrypt(BigInteger [] cipher, GMPrivateKey private_key) {
		BigInteger e;
		BigInteger m = BigInteger.ZERO;
		for (int i = cipher.length - 1; i >= 0 ; i--) {
			e = NTL.jacobi(cipher[i], private_key.p);
			if (e.equals(NEG_ONE)) {
				m = m.setBit(i);
			}
		}
		return m;
	}

	/**
	 * XOR the encrypted bits of Goldwasser-Micali
	 * @param cipher_1 - Goldwasser-Micali encrypted ciphertext
	 * @param cipher_2 - Goldwasser-Micali encrypted ciphertext
	 * @param public_key - Goldwasser-Micali public key used to encrypt the inputted ciphertexts
	 * @return XORed encrypted ciphertexts
	 */
	public static BigInteger[] xor(BigInteger [] cipher_1, BigInteger[] cipher_2, GMPublicKey public_key) 
			throws HomomorphicException {
		if(cipher_1.length != cipher_2.length) {
			throw new HomomorphicException("Unequal Size of Ciphertext for XOR!");
		}
		BigInteger [] xor_solution = new BigInteger[cipher_1.length];
		for (int i = cipher_1.length - 1; i >= 0 ; i--) {
			xor_solution[i] = cipher_1[i].multiply(cipher_2[i]).mod(public_key.n);
		}
		return xor_solution;
	}
}
