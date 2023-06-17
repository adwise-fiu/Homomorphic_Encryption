# Homomorphic Encryption
[![Build Gradle project](https://github.com/AndrewQuijano/Homomorphic_Encryption/actions/workflows/build-gradle-project.yml/badge.svg)](https://github.com/AndrewQuijano/Homomorphic_Encryption/actions/workflows/build-gradle-project.yml)

[![codecov](https://codecov.io/gh/AndrewQuijano/Homomorphic_Encryption/branch/master/graph/badge.svg?token=OIFWDVX2SA)](https://codecov.io/gh/AndrewQuijano/Homomorphic_Encryption)

Homomorphic Encryption is a Java library that implements the following partially homomorphic encryption systems:
* Paillier  
* El-Gamal (Additive or multiplicative)  
* Goldwasser-Micali  
* DGK  

As the partially homomorphic encryption systems only support addition with two ciphertexts, other protocols been appended to extend its functionality, in particular:
* Secure Multiplication
* Secure Division
* Secure Comparison

## Installation
Please retrieve the JAR file from [here](https://github.com/AndrewQuijano/Homomorphic_Encryption/tags)

As this library uses Java 8, the JAR file can be imported into an Android project.
If you want to review/edit the library, import the JAVA_PHE directory into an Eclipse project and edit as necessary. The Main.java folder only exists for testing and provide examples of how to use the library.

## Generate Keys
To create the keys, run the following commands:
```bash
gradle -g gradle_user_home run -PchooseRole=security.paillier.PaillierKeyPairGenerator
gradle -g gradle_user_home run -PchooseRole=security.dgk.DGKKeyPairGenerator
```
This will create the key files on the current working directory. It will also

## Create JAR file to import into another project
To create the JAR file to import into another project, run the following:
```bash
./gradlew build
./gradlew jar
```
You will find a `crypto.jar` file in the `build/libs/` directory.

## Usage
Import the packages as necessary. For basic usage please check Server.java in the test package for basic usage of these cryptography libraries.
Please view Client.java and Server.java for an example how to compare encrypted numbers, secure multiplication, secure division, etc. 

### security.socialistmillionaire.alice
**Initialize**
```java
public class demo {
    public static void main(String[] args) {
        alice Niu = new alice(new Socket("192.168.1.208", 9254));
        // These Public Keys are made by Bob and automatically sent to Alice.
        PaillierPublicKey pk = Niu.getPaillierPublicKey();
        DGKPublicKey pubKey = Niu.getDGKPublicKey();
        ElGamalPublicKey e_pk = Niu.getElGamalPublicKey();
    }
}
```
**Protocol1(x)**
See Protocol 1 in "Improving the DGK comparison protocol" in Alice section.
Compare with plaintext value y Bob has.
* Parameters
    * plaintext (**BigInteger**)
* Returns
    * value (**boolean**) - x <= y    
* Raises (**HomomorphicException**)
    * If the plaintext has more bits than what the DGK public key supports.

**Protocol2(x, y)**
See Protocol 2 in "Improving the DGK comparison protocol" in Alice section.
* Parameters
    * x (**BigInteger**) - a Paillier/DGK encrypted value
    * y (**BigInteger**) - a Paillier/DGK encrypted value
* Returns
    * value (**boolean**) - x >= y
* Raises (**HomomorphicException**)
    * N/A

**Protocol3(x)**
See Protocol 3 in "Improving the DGK comparison protocol" in Alice section. Compare with plaintext value y held by bob
* Parameters
    * x (**BigInteger**) - plaintext
* Returns
    * value (**boolean**) - x <= y    
* Raises (**HomomorphicException**)
    * If the plaintext has more bits than what the DGK public key supports

**Modified_Protocol3(x)**
See Protocol 3 in "Correction to 'Improving the DGK comparison protocol'" in Alice section. View the sub-protocol.
* Parameters
    * x (**BigInteger**) - plaintext
* Returns
    * value (**boolean**) - x <= y    
* Raises (**HomomorphicException**)
    * N/A

**Protocol4(x, y)**
See Protocol 3 in "Correct to 'Improving the DGK comparison protocol'" in Alice section.
* Parameters
    * x (**BigInteger**) - Paillier or DGK encrypted value
    * y (**BigInteger**) - Paillier or DGK encrypted value
* Returns
    * value (**boolean**) - x >= y    
* Raises (**HomomorphicException**)
    * 
```java
BigInteger x = new BigInteger("50");
BigInteger y = new BigInteger("51");

// Note: Assume bob is sharing y = new BigInteger("55");
Niu.Protocol1(x); // TRUE, X <= Y
Niu.Protocol3(x);// TRUE X <= Y
Niu.Modified_Protocol3(x); // TRUE X <= Y

// Note: Protocol 2 only works with Paillier encrypted values!
// Note: Protocol 2/4 works with Paillier/DGK encrypted values!
x = PaillierCipher.encrypt(x, pk); 
y = PaillierCipher.encrypt(y, pk);
Niu.Protocol2(x, y); // FALSE, b.c X >= Y is FALSE
Niu.Protocol4(x, y); // FALSE: b.c X >= Y is FALSE
```
**division(x, y)**
Please review Protocol 2 in the "Encrypted Integer Division" paper by Thjis Veugen
* Parameters
    * x (**BigInteger**) - Paillier or DGK encrypted value
    * d (**BigInteger**) - plaintext value
* Returns
    * ciphertext (**BigInteger**) - x/d
* Raises (**HomomorphicException**)
    * Constraints: 0 <= x <= N * 2^{-sigma} and 0 <= d < N

**multiplication(x, y)**
* Parameters
    * x (**BigInteger**) - Paillier or DGK encrypted value
    * y (**BigInteger**) - Paillier or DGK encrypted value
* Returns
    * ciphertext (**BigInteger**) - x * y
* Raises (**HomomorphicException**)
    * Constraints: 0 <= x <= N * 2^{-sigma} and 0 <= d < N

**bubbleSort(arr)**
* Parameters
    * arr (**BigInteger**) - List of Paillier or DGK encrypted value
* Returns
    * N/A - arr is list of sorted encrypted values from low to high
* Raises (**HomomorphicException**)
    * N/A

**getKMax(arr, k)**
* Parameters
    * arr (**List<BigInteger>**) - List of Paillier or DGK encrypted value
    * k - get number of k largest encrypted numbers
* Returns
    * a (**List<BigInteger>**) - new array of size k sorted from low to high
* Raises (**HomomorphicException**)
    * N/A

**getKMin(arr, k)**
* Parameters
    * arr (**List<BigInteger>**) - List of Paillier or DGK encrypted value
    * k - get number of k smallest encrypted numbers
* Returns
    * a (**List<BigInteger>**) - new array of size k sorted from low to high
* Raises (**HomomorphicException**)
    * N/A

### security.socialistmillionaire.bob
**Initialize**
```java
ServerSocket bob_socket = null;
Socket bob_client = null;
int KEY_SIZE = 1024;
bob andrew = null;
    	
// Build all Key Pairs
PaillierKeyPairGenerator p = new PaillierKeyPairGenerator();
p.initialize(KEY_SIZE, null);
KeyPair pe = p.generateKeyPair();

DGKKeyPairGenerator d = new DGKKeyPairGenerator();
d.initialize(KEY_SIZE, null);
KeyPair DGK = d.generateKeyPair();
    	
ElGamalKeyPairGenerator pg = new ElGamalKeyPairGenerator();
pg.initialize(KEY_SIZE, new SecureRandom());
KeyPair el_gamal = pg.generateKeyPair();
    		
bob_socket = new ServerSocket(9254);
bob_client = bob_socket.accept();
    	
// Note: Alice automatically gets the public keys!
andrew = new bob(bob_client, pe, DGK, el_gamal);
```
**Protocol1(y)**
See Protocol 1 in "Improving the DGK comparison protocol" in Bob section.
Compare with plaintext value y Bob has.
* Parameters
    * plaintext (**BigInteger**)
* Returns
    * value (**boolean**) - x <= y    
* Raises (**HomomorphicException**)
    * If the plaintext has more bits than what the DGK public key supports.

**Protocol2()**
See Protocol 2 in "Improving the DGK comparison protocol" in Bob section.
* Parameters
    * N/A
* Returns
    * value (**boolean**) - x >= y
* Raises (**HomomorphicException**)
    * N/A

**Protocol3(y)**
See Protocol 3 in "Improving the DGK comparison protocol" in Bob section. Compare with plaintext value y held by bob
* Parameters
    * y (**BigInteger**) - plaintext
* Returns
    * value (**boolean**) - x <= y    
* Raises (**HomomorphicException**)
    * If the plaintext has more bits than what the DGK public key supports

**Modified_Protocol3(y)**
See Protocol 3 in "Correction to 'Improving the DGK comparison protocol'" in Bob section. View the sub-protocol.
* Parameters
    * y (**BigInteger**) - plaintext
* Returns
    * value (**boolean**) - x <= y    
* Raises (**HomomorphicException**)
    * N/A

**Protocol4()**
See Protocol 3 in "Correct to 'Improving the DGK comparison protocol'" in Bob section.
* Parameters
    * N/A
* Returns
    * value (**boolean**) - x >= y    
* Raises (**HomomorphicException**)
    * 
```java

```
**division(x, y)**
Please review Protocol 2 in the "Encrypted Integer Division" paper by Thjis Veugen
* Parameters
    * d (**BigInteger**) - plaintext value
* Returns
    * N/A
* Raises (**HomomorphicException**)
    * Constraints: 0 <= x <= N * 2^{-sigma} and 0 <= d < N

**multiplication()**
Please review 'Correction of a Secure Comparison Protocol for Encrypted Integers in IEEE WIFS 2012 (Short Paper)' by Mau et al., page 3, an outsourced multiplication section.
* Parameters
    * N/A
* Returns
    * N/A
* Raises (**HomomorphicException**)
    * Constraints: 0 <= x <= N * 2^{-sigma} and 0 <= d < N

### security.dgk
**Generate DGK Keys**
```java
int KEY_SIZE = 1024; //number of bits
SecureRandom r = new SecureRandom();
DGKKeyPairGenerator p = new DGKKeyPairGenerator();
p.initialize(KEY_SIZE, r);
KeyPair pe = p.generateKeyPair();
DGKPublicKey pk = (DGKPublicKey) pe.getPublic();
DGKPrivateKey sk = (DGKPrivateKey) pe.getPrivate();
```

**encrypt(plaintext, pk)**
Encrypt a plain-text BigInteger using the DGK Cryptography system.
* Parameters
    * plaintext (**long**)
    * pk (**DGKPublicKey**)
* Returns
    * ciphertext (**BigInteger**)    
* Raises (**HomomorphicException**)
    * If the plaintext is negative or exceeds plaintext space that can be handled by the DGK Public Key, this exception will be generated.

**decrypt(ciphertext, sk)**
Decrypt a cipher-text BigInteger using the DGK Cryptography system.
* Parameters
    * ciphertext (**BigInteger**)
    * sk (**DGKPrivateKey**)
* Returns
    * plaintext (**long**)    
* Raises (**HomomorphicException**)
    * If the ciphertext is negative or exceeds ciphertext space that can be handled by the DGK Private Key, this exception will be generated.
```java
BigInteger c = DGKOperations.encrypt(10, pk);
long d = DGKOperations.decrypt(c, pk); // d = 10
```

**add(ciphertext1, ciphertext2, pk)**
Add the results of both ciphertexts.
* Parameters
    * ciphertext1 (**BigInteger**) - a DGK ciphertext
    * ciphertext2 (**BigInteger**) - a second DGK ciphertext
    * pk (**DGKPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of both ciphertexts    
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the sum of the ciphertexts exceeds the plaintext space of supported by the DGK public key, the sum is subject to mod N, the size of the plaintext space.     

**add_plaintext(ciphertext, plaintext, pk)**
Add the value in plaintext within the ciphertext. This is much faster than regular add as you save an encryption operation.
* Parameters
    * ciphertext (**BigInteger**) - a DGK ciphertext
    * plaintext (**BigInteger**) - a BigInteger plaintext
    * pk (**DGKPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of both the ciphertext and plaintext
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the sum of the ciphertexts exceeds the plaintext space of supported by the DGK public key, the sum is subject to mod u, the size of the plaintext space.      

```java
// Addition
BigInteger c = DGKOperations.encrypt(10, pk);
c = DGKOperations.add(c, c, pk); 
// c = 10 + 10 = 20. Notice both arguments need to be encrypted. c is still encrypted!
// Scalar addition
BigInteger d = DGKOperations.encrypt(10, pk);
d = DGKOperations.add_plaintext(d, 10, pk);
// d = 10 + 10 = 20. The second argument must be a plaintext if using plaintext addition! 
// d is still encrypted!
```
**subtract(ciphertext1, ciphertext2, pk)**
Subtract the results of both ciphertexts.
* Parameters
    * ciphertext1 (**BigInteger**) - a DGK ciphertext
    * ciphertext2 (**BigInteger**) - a second DGK ciphertext
    * pk (**DGKPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted subtraction of ciphertext1 and ciphertext2.
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the value encrypted in ciphertext2 is greater than the value encrypted in ciphertext1, the value is not negative, it would be congruent to a positive value mod u when decrypted. 

**subtract_plaintext(ciphertext, plaintext, pk)**
Subtract the value in plaintext with the ciphertext. This is much faster than regular subtraction as you save an encryption operation.
* Parameters
    * ciphertext (**BigInteger**) - a DGK ciphertext
    * plaintext (**BigInteger**) - a BigInteger plaintext
    * pk (**DGKPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of both the ciphertext and plaintext
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the value encrypted in ciphertext2 is greater than the value encrypted in ciphertext1, the value is not negative, it would be congruent to a positive value mod u when decrypted. 

```java
c = DGKOperations.encrypt(10, pk);
c = DGKOperations.multiply(c, 10, pk);
// c = 10 * 10 = 100. 
// First argument is cipher-text, second is plain-text value
```
**multiply(ciphertext, plaintext, pk)**
Multiply the encrypted value in the ciphertext with the plaintext
* Parameters
    * ciphertext (**BigInteger**) - a DGK ciphertext
    * plaintext (**BigInteger**) - a plaintext BigInteger
    * pk (**DGKPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted multiplication of ciphertext and plaintext.
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the product explains the plaintext space, it is subject to mod u, the plain-text space.

**divide(ciphertext, plaintext, pk)**
Divide the encrypted value in the ciphertext with the plaintext
* Parameters
    * ciphertext (**BigInteger**) - a DGK ciphertext
    * plaintext (**BigInteger**) - a plaintext BigInteger
    * pk (**DGKPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted ciphertext divided by the plaintext.
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If you do this, you need to make sure that the plaintext divides the value encrypted in the ciphertext! Otherwise, you will get a horribly wrong answer! You should use the Division Protocol if you can't make this guarantee on the Socialist Millionaire's package!

### security.elgamal
**Generate ElGamal Keys**
```java
int KEY_SIZE = 1024; //number of bits
SecureRandom r = new SecureRandom();
ElGamalKeyPairGenerator p = new ElGamalKeyPairGenerator();
p.initialize(KEY_SIZE, r);
KeyPair pe = p.generateKeyPair();
ElGamalPublicKey pk = (ElGamalPublicKey) pe.getPublic();
ElGamalPrivateKey sk = (ElGamalPrivateKey) pe.getPrivate();
```

**encrypt(plaintext, pk)**
Encrypt a plain-text BigInteger using the ElGamal Cryptography system.
* Parameters
    * plaintext (**BigInteger**)
    * pk (**ElGamalPublicKey**)
* Returns
    * ciphertext (**ElGamal_Ciphertext**)    
* Raises (**HomomorphicException**)
    * If the plaintext is negative or exceeds plaintext space that can be handled by the ElGamal Public Key, this exception will be generated.

**decrypt(ciphertext, sk)**
Decrypt a cipher-text BigInteger using the ElGamal Cryptography system.
* Parameters
    * ciphertext (**ElGamal_Ciphertext**)
    * sk (**ElGamalPrivateKey**)
* Returns
    * plaintext (**BigInteger**)    
* Raises (**HomomorphicException**)
    * If the ciphertext is negative or exceeds ciphertext space that can be handled by the ElGamal Private Key, this exception will be generated.
```java
BigInteger c = PaillierCipher.encrypt(BigInteger.TEN, pk);
c = PaillierCipher.decrypt(c, pk); // c = 10
```

**add(ciphertext1, ciphertext2, pk)**
Add the results of both ciphertexts.
* Parameters
    * ciphertext1 (**ElGamal_ciphertext**) - a ElGamal ciphertext
    * ciphertext2 (**ElGamal_ciphertext**) - a second ElGamal ciphertext
    * pk (**ElGamalPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of both ciphertexts    
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the sum of the ciphertexts exceeds the plaintext space of supported by the Paillier public key, the sum is subject to mod N, the size of the plaintext space.     

**add_plaintext(ciphertext, plaintext, pk)**
Add the value in plaintext within the ciphertext. This is much faster than regular add as you save an encryption operation.
* Parameters
    * ciphertext (**ElGamal_ciphertext**) - a ElGamal ciphertext
    * plaintext (**BigInteger**) - a BigInteger plaintext
    * pk (**ElGamalPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of both the ciphertext and plaintext
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the sum of the ciphertexts exceeds the plaintext space of supported by the ElGamal public key, the sum is subject to mod N, the size of the plaintext space.      

```java
// Addition
ElGamal_Ciphertext c = ElGamalCipher.encrypt(BigInteger.TEN, pk);
c = ElGamalCipher.add(c, c, pk); 
// c = 10 + 10 = 20. Notice both arguments need to be encrypted. c is still encrypted!
// Scalar addition
ElGamal_Ciphertext d = ElGamalCipher.encrypt(BigInteger.TEN, pk);
d = ElGamalCipher.add_plaintext(d, BigInteger.TEN, pk);
// d = 10 + 10 = 20. The second argument must be a plaintext if using plaintext addition! 
// d is still encrypted!
```
**subtract(ciphertext1, ciphertext2, pk)**
Subtract the results of both ciphertexts.
* Parameters
    * ciphertext1 (**ElGamal_ciphertext**) - a ElGamal ciphertext
    * ciphertext2 (**ElGamal_ciphertext**) - a second ElGamal ciphertext
    * pk (**ElGamalPublicKey**)
* Returns
    * ciphertext (**ElGamal_ciphertext**) - This ciphertext is the encrypted subtraction of ciphertext1 and ciphertext2.
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the value encrypted in ciphertext2 is greater than the value encrypted in ciphertext1, the value is not negative, it would be congruent to a positive value mod N when decrypted. 

**subtract_plaintext(ciphertext, plaintext, pk)**
Subtract the value in plaintext with the ciphertext. This is much faster than regular subtraction as you save an encryption operation.
* Parameters
    * ciphertext (**ElGamal_ciphertext**) - a ElGamal ciphertext
    * plaintext (**BigInteger**) - a BigInteger plaintext
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**ElGamal_ciphertext**) - This ciphertext is the encrypted sum of both the ciphertext and plaintext
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the value encrypted in ciphertext2 is greater than the value encrypted in ciphertext1, the value is not negative, it would be congruent to a positive value mod N when decrypted. 

```java
c = ElGamalCipher.encrypt(BigInteger.TEN, pk);
c = ElGamalCipher.multiply(c, BigInteger.TEN, pk);
// c = 10 * 10 = 100. 
// First argument is cipher-text, second is plain-text value
```
**multiply(ciphertext, plaintext, pk)**
Multiply the encrypted value in the ciphertext with the plaintext
* Parameters
    * ciphertext (**ElGamal_ciphertext**) - a ElGamal ciphertext
    * plaintext (**BigInteger**) - a plaintext BigInteger
    * pk (**ElGamalPublicKey**)
* Returns
    * ciphertext (**ElGamal_ciphertext**) - This ciphertext is the encrypted multiplication of ciphertext and plaintext.
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the product explains the plaintext space, it is subject to mod N, the plain-text space.

**divide(ciphertext, plaintext, pk)**
Divide the encrypted value in the ciphertext with the plaintext
* Parameters
    * ciphertext (**ElGamal_ciphertext**) - a ElGamal ciphertext
    * plaintext (**BigInteger**) - a plaintext BigInteger
    * pk (**ElGamalPublicKey**)
* Returns
    * ciphertext (**ElGamal_ciphertext**) - This ciphertext is the encrypted ciphertext divided by the plaintext.
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If you do this, you need to make sure that the plaintext divides the value encrypted in the ciphertext! Otherwise, you will get a horribly wrong answer! You should use the Division Protocol if you can't make this guarantee on the Socialist Millionaire's package!

### security.gm
**Generate Goldwasser-Micali Keys**
```java
GMKeyPairGenerator gmg = new GMKeyPairGenerator();
gmg.initialize(KEY_SIZE, null);
KeyPair gm = gmg.generateKeyPair();
GMPublicKey gm_pk = (GMPublicKey) gm.getPublic();
GMPrivateKey gm_sk = (GMPrivateKey) gm.getPrivate();
```

**encrypt(plaintext, pk)**
Encrypt a plain-text BigInteger using the Goldwasser-Micali Cryptography system.
* Parameters
    * plaintext (**BigInteger**)
    * pk (**GMPublicKey**)
* Returns
    * ciphertext (**List<BigInteger>**)    
* Raises (**HomomorphicException**)
    * N/A

**decrypt(ciphertext, sk)**
Decrypt a cipher-text using the Goldwasser-Micali Cryptography system.
* Parameters
    * ciphertext (**List<BigInteger>**)
    * sk (**GMPrivateKey**)
* Returns
    * plaintext (**BigInteger**)    
* Raises (**HomomorphicException**)
    * N/A
```java
List<BigInteger> c = GMCipher.encrypt(BigInteger.TEN, gm_pk);
BigInteger d = GMCipher.decrypt(c, pk); // c = 10
```

**xor(ciphertext1, ciphertext2, pk)**
XOR both ciphertexts.
* Parameters
    * ciphertext1 (**List<BigInteger>**) - a Goldwasser-Micali ciphertext
    * ciphertext2 (**List<BigInteger>**) - a second Goldwasser-Micali ciphertext
    * pk (**GMPublicKey**)
* Returns
    * ciphertext (**List<BigInteger>**) - This ciphertext is the encrypted xor of both ciphertexts    
* Raises (**HomomorphicException**)
    * If both ciphertexts don't have the same number of bits, an exception will be thrown.
**

### security.paillier

**Generate Paillier Keys**
```java
int KEY_SIZE = 1024; //number of bits
SecureRandom r = new SecureRandom();
PaillierKeyPairGenerator p = new PaillierKeyPairGenerator();
p.initialize(KEY_SIZE, r);
KeyPair pe = p.generateKeyPair();
PaillierPublicKey pk = (PaillierPublicKey) pe.getPublic();
PaillierPrivateKey sk = (PaillierPrivateKey) pe.getPrivate();
```

**encrypt(plaintext, pk)**
Encrypt a plain-text BigInteger using the Paillier Cryptography system.
* Parameters
    * plaintext (**BigInteger**)
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**BigInteger**)    
* Raises (**HomomorphicException**)
    * If the plaintext is negative or exceeds plaintext space that can be handled by the Paillier Public Key, this exception will be generated.

**decrypt(ciphertext, sk)**
Decrypt a cipher-text BigInteger using the Paillier Cryptography system.
* Parameters
    * ciphertext (**BigInteger**)
    * sk (**PaillierPrivateKey**)
* Returns
    * plaintext (**BigInteger**)    
* Raises (**HomomorphicException**)
    * If the ciphertext is negative or exceeds ciphertext space that can be handled by the Paillier Private Key, this exception will be generated.
```java
BigInteger c = PaillierCipher.encrypt(BigInteger.TEN, pk);
c = PaillierCipher.decrypt(c, pk); // c = 10
```

**add(ciphertext1, ciphertext2, pk)**
Add the results of both ciphertexts.
* Parameters
    * ciphertext1 (**BigInteger**) - a Paillier ciphertext
    * ciphertext2 (**BigInteger**) - a second Paillier ciphertext
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of both ciphertexts    
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the sum of the ciphertexts exceeds the plaintext space of supported by the Paillier public key, the sum is subject to mod N, the size of the plaintext space.     

**add_plaintext(ciphertext, plaintext, pk)**
Add the value in plaintext within the ciphertext. This is much faster than regular add as you save an encryption operation.
* Parameters
    * ciphertext (**BigInteger**) - a Paillier ciphertext
    * plaintext (**BigInteger**) - a BigInteger plaintext
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of both the ciphertext and plaintext
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the sum of the ciphertexts exceeds the plaintext space of supported by the Paillier public key, the sum is subject to mod N, the size of the plaintext space.      

```java
// Addition
BigInteger c = PaillierCipher.encrypt(BigInteger.TEN, pk);
c = PaillierCipher.add(c, c, pk); 
// c = 10 + 10 = 20. Notice both arguments need to be encrypted. c is still encrypted!
// Scalar addition
BigInteger d = PaillierCipher.encrypt(BigInteger.TEN, pk);
d = PaillierCipher.add_plaintext(d, BigInteger.TEN, pk);
// d = 10 + 10 = 20. The second argument must be a plaintext if using plaintext addition! 
// d is still encrypted!
```
**subtract(ciphertext1, ciphertext2, pk)**
Subtract the results of both ciphertexts.
* Parameters
    * ciphertext1 (**BigInteger**) - a Paillier ciphertext
    * ciphertext2 (**BigInteger**) - a second Paillier ciphertext
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted subtraction of ciphertext1 and ciphertext2.
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the value encrypted in ciphertext2 is greater than the value encrypted in ciphertext1, the value is not negative, it would be congruent to a positive value mod N when decrypted. 

**subtract_plaintext(ciphertext, plaintext, pk)**
Subtract the value in plaintext with the ciphertext. This is much faster than regular subtraction as you save an encryption operation.
* Parameters
    * ciphertext (**BigInteger**) - a Paillier ciphertext
    * plaintext (**BigInteger**) - a BigInteger plaintext
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of both the ciphertext and plaintext
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the value encrypted in ciphertext2 is greater than the value encrypted in ciphertext1, the value is not negative, it would be congruent to a positive value mod N when decrypted. 

```java
c = PaillierCipher.encrypt(BigInteger.TEN, pk);
c = PaillierCipher.multiply(c, BigInteger.TEN, pk);
// c = 10 * 10 = 100. 
// First argument is cipher-text, second is plain-text value
```
**multiply(ciphertext, plaintext, pk)**
Multiply the encrypted value in the ciphertext with the plaintext
* Parameters
    * ciphertext (**BigInteger**) - a Paillier ciphertext
    * plaintext (**BigInteger**) - a plaintext BigInteger
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted multiplication of ciphertext and plaintext.
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If the product explains the plaintext space, it is subject to mod N, the plain-text space.

**divide(ciphertext, plaintext, pk)**
Divide the encrypted value in the ciphertext with the plaintext
* Parameters
    * ciphertext (**BigInteger**) - a Paillier ciphertext
    * plaintext (**BigInteger**) - a plaintext BigInteger
    * pk (**PaillierPublicKey**)
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted ciphertext divided by the plaintext.
* Raises (**HomomorphicException**)
    * N/A
* Warning:
    * If you do this, you need to make sure that the plaintext divides the value encrypted in the ciphertext! Otherwise, you will get a horribly wrong answer! You should use the Division Protocol if you can't make this guarantee on the Socialist Millionaire's package!

**sum(ciphertext, pk)**
Compute the sum of all ciphertexts
* Parameters
    * ciphertext (**List<BigInteger>**) - a List of Paillier ciphertexts
    * pk (**PaillierPublicKey**) - used to sum all ciphertexts
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of all values in the list of ciphertext
* Raises (**HomomorphicException**)
    * N/A

**sum(ciphertext, pk, limit)**
Compute the sum of all ciphertexts from 0 up to the index specified by limit.
* Parameters
    * ciphertext (**List<BigInteger>**) - a List of Paillier ciphertexts
    * pk (**PaillierPublicKey**) - used to sum all ciphertexts
    * limit (**int**) - index to sum up to.
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of all values in the list of ciphertext up to the limit.
* Raises (**HomomorphicException**)
    * N/A

**sum_product(ciphertext, plaintext pk)**
Compute the product of each ciphertext and plaintext. Then sum all the products.
* Parameters
    * ciphertext (**List<BigInteger>**) - a List of Paillier ciphertexts
    * plaintext (**List<BigInteger>**) - a List of plaintext values
    * pk (**PaillierPublicKey**) - used to compute sum and product
* Returns
    * ciphertext (**BigInteger**) - This ciphertext is the encrypted sum of products of the list of ciphertext and plaintexts.
* Raises (**HomomorphicException**)
    * If the size of the list of ciphertexts and plaintext are not equal.

**sign(plaintext, sk)**
Sign the plaintext using a Paillier Private Key.
* Parameters
    * plaintext (**BigInteger**) - plaintext
    * sk (**PaillierPrivateKey**) - used to sign the BigInteger
* Returns
    * signature (**BigInteger**) - The signed BigInteger 
* Raises (**HomomorphicException**)
    * N/A

**verify(plaintext, signature, pk)**
Verify the signature using the Paillier Public Key
* Parameters
    * plaintext (**BigInteger**) - plaintext that is supposedly signed
    * signature (**BigInteger**) - signed bytes with its corresponding PaillierPrivateKey
    * pk (**PaillierPublicKey**) - used to verify the signature
* Returns
    * valid (**boolean**) - true if valid, false if not valid 
* Raises (**HomomorphicException**)
    * N/A

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Authors and acknowledgment
Code author: Andrew Quijano  

| Name/Title with Link | Authors | Venue | Description
| ------------- | ------------- |  ------------- | ------------- |
| [Server-Side Fingerprint-Based Indoor Localization Using Encrypted Sorting](https://arxiv.org/abs/2008.11612) | Andrew Quijano and Kemal Akkaya | IEEE MASS 2019 | This paper is implemented the libaray in this repository
| [Efficient and Secure Comparison for On-Line Auctions](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.215.5941&rep=rep1&type=pdf) | Ivan Damgaard, Martin Geisler, and Mikkel Kroigaard | Australasian conference on information security and privacy. | This paper is the first introduction to DGK. There is a correction to this paper listed [here](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.215.5941&rep=rep1&type=pdf)
|[Improving the DGK comparison protocol](citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.456.5314&rep=rep1&type=pdf)| Thijs Veugen | 2012 IEEE International Workshop on Information Forensics and Security (WIFS) | This paper describes improvements to the DGK comparison protocol. Protocol 4 had a correction shown [here](https://eprint.iacr.org/2018/1100.pdf)
 |[Encrypted Integer Division](https://www.academia.edu/download/51716137/Encrypted_integer_division20170209-12588-kq9aar.pdf)| Thijis Veugen | 2010 IEEE International Workshop on Information Forensics and Security | This repository implements Protocol 2 for Encrypted Division
 |[Correction of a Secure Comparison Protocol for Encrypted Integers in IEEE WIFS 2012](https://link.springer.com/chapter/10.1007/978-3-319-64200-0_11) | Baptiste Vinh Mau & Koji Nuida | 2012 IEEE International Workshop on Information Forensics and Security (WIFS) | This paper describes a secure multiplication protocol used in this repository
 |[A Secure and Optimally Efficient Multi-Authority Election Scheme](citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.57.127&rep=rep1&type=pdf)| Ronald Cramer, Rosario Gennaro, Berry Schoenmakers | | This paper describes how El-Gamal was implemented in this repo
 |[Public-Key Cryptosystems Based on Composite Degree Residuosity Classes](https://link.springer.com/content/pdf/10.1007/3-540-48910-X_16.pdf) | Pascal Paillier | International conference on the theory and applications of cryptographic techniques | This paper is the original paper describing Paillier, which is how it is currently implemented as it has certain advantages over other variations

The work to create this repository was initially funded by the US NSF REU Site at FIU under the grant number REU CNS-1461119.  

## License
[MIT](https://choosealicense.com/licenses/mit/)

## Project status
The project is currently fully tested.
Currently, the stretch goal is to implement certificates using the Bouncy Castle API for these homomorphic encryption systems.
