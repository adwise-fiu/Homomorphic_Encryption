# Homomorphic Encryption
[![Build Gradle project](https://github.com/adwise-fiu/Homomorphic_Encryption/actions/workflows/test_library.yml/badge.svg)](https://github.com/adwise-fiu/Homomorphic_Encryption/actions/workflows/test_library.yml)

[![codecov](https://codecov.io/gh/adwise-fiu/Homomorphic_Encryption/graph/badge.svg?token=OIFWDVX2SA)](https://codecov.io/gh/adwise-fiu/Homomorphic_Encryption)

Homomorphic Encryption is a Java library that implements the following partially homomorphic encryption systems:
* Paillier  
* El-Gamal (Additive or multiplicative)  
* Goldwasser-Micali  
* DGK  

As the partially homomorphic encryption systems only support addition with two ciphertexts, 
other protocols have been appended to extend its functionality, in particular:
* Secure Multiplication
* Secure Division
* Secure Comparison

Thjis Veugen implemented various of [these protocols in Python](https://github.com/TNO-PET/).

## Installation
Please retrieve the JAR file from [here](https://github.com/adwise-fiu/Homomorphic_Encryption/releases). 
Instead, you can also now import the file via [Maven Central](https://central.sonatype.com/artifact/io.github.andrewquijano/ciphercraft/overview).

Alternatively, you can download the repository and create the JAR file to import into another project
by running the following command, you will find a `ciphercraft-{version}.jar` file in the `build/libs/` directory.
```bash
./gradlew jar
```

### Minimum required steps
We used ObjectInputValidatingStreams,
so if you use Gradle, import the [Apache Common IO library](https://commons.apache.org/proper/commons-io/) into your project as well with the library.

### Optional—Track the number of bytes
If you want to track the number of bytes sent by Alice/Bob, we also added instrumentation.
To install this, there are more steps:
1. You need to include the InstrumentationAgent.jar file
2. We also need to make the following changes to your build.gradle

To build the jar file from the root of the repository, run these commands and move the jar file into the libs folder:
```bash
javac -d output src/main/java/edu/fiu/adwise/homomorphic_encryption/misc/InstrumentationAgent.java
jar cfm InstrumentationAgent.jar src/main/java/edu/fiu/adwise/homomorphic_encryption/misc/MANIFEST.mf -C output .
```

If you want to enable tracking the number of bytes used when testing, you need the JVM arguments
```gradle
test {
    testLogging {
// Make sure output from
// standard out or error is shown
// in Gradle output.
        showStandardStreams = true
    }

    // Set JVM arguments to include your agent
    jvmArgs = [
            '-javaagent:libs/InstrumentationAgent.jar' // Change this to your agent JAR path
    ]
}
```
You would also need to upgrade your run in `build.gradle` as follows with JVM argument and passing arguments with -P:

```gradle
// Define a task to run your Java application with the agent
tasks.register('runWithAgent', JavaExec) {
    mainClass.set(project.findProperty("chooseRole").toString())
    classpath = sourceSets.main.runtimeClasspath

    // Set JVM arguments to include your agent
    jvmArgs = [
            '-javaagent:libs/InstrumentationAgent.jar'
    ]

    // Pass command-line arguments to your application
    // gradle run -PchooseRole=PathsBob -Pargs='./data/ownroute3.txt 9000'
    if (project.hasProperty('args')) {
        args project.args.split(' ')
    }
}

// Configure the 'run' task to depend on 'runWithAgent'
tasks.run.dependsOn('runWithAgent')
```

### Other projects using this library
This library was used in the following research projects, linked here.
1. [Secure Indoor Localization](https://github.com/adwise-fiu/Secure_Indoor_Localization)
2. [Enhanced Privacy Preserving Decision Trees](https://github.com/adwise-fiu/Level-Site-PPDT)
3. [Secure Drone path for collision avoidance](https://github.com/adwise-fiu/homomorphic-path-comparison/)

The `ciphercraft-{version}.jar` file is imported in the `libs` directory.

## Generate Keys
To create the keys, run the following commands:
```bash
gradle -g gradle_user_home run -PchooseRole=security.paillier.PaillierKeyPairGenerator
gradle -g gradle_user_home run -PchooseRole=security.dgk.DGKKeyPairGenerator
```
This will create the key files in the current working directory.

## Documentation
The documentation for this repository is maintained via Javadoc. You can create this as follows:
```bash
./gradlew generateJavadoc
```

Alternatively,
you can find the documentation from my website [here](https://andrewquijano.github.io/files/homomorphic_encryption/). 
Please check under `src/test/java/edu/fiu/adwise/encryption_test` for the test cases,
which also has detailed examples on how to use the API for your secure computations.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Authors and acknowledgment
Code author: Andrew Quijano  

| Name/Title with Link                                                                                                                                 | Authors                                             | Venue                                                                               | Description                                                                                                                                                                          |
|------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------|-------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Server-Side Fingerprint-Based Indoor Localization Using Encrypted Sorting](https://arxiv.org/abs/2008.11612)                                        | Andrew Quijano and Kemal Akkaya                     | IEEE MASS 2019                                                                      | This paper is implemented the library in this repository                                                                                                                             |
| [Efficient and Secure Comparison for On-Line Auctions](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.215.5941&rep=rep1&type=pdf)         | Ivan Damgaard, Martin Geisler, and Mikkel Kroigaard | Australasian conference on information security and privacy.                        | This paper is the first introduction to DGK. There is a correction to this paper listed [here](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.215.5941&rep=rep1&type=pdf) |
| [Improving the DGK comparison protocol](https://publications.tno.nl/publication/100415/HOfBCj/veugen-2012-improving.pdf)                                | Thijis Veugen                                       | 2012 IEEE International Workshop on Information Forensics and Security (WIFS)       | This paper describes improvements to the DGK comparison protocol. Protocol 4 had a correction shown [here](https://eprint.iacr.org/2018/1100.pdf)                                    |
| [Encrypted Integer Division](https://www.academia.edu/download/51716137/Encrypted_integer_division20170209-12588-kq9aar.pdf)                         | Thijis Veugen                                       | 2010 IEEE International Workshop on Information Forensics and Security              | This repository implements Protocol 2 for Encrypted Division                                                                                                                         |
| [Correction of a Secure Comparison Protocol for Encrypted Integers in IEEE WIFS 2012](https://link.springer.com/chapter/10.1007/978-3-319-64200-0_11) | Baptiste Vinh Mau & Koji Nuida                      | 2012 IEEE International Workshop on Information Forensics and Security (WIFS)       | This paper describes a secure multiplication protocol used in this repository                                                                                                        |
| [A Secure and Optimally Efficient Multi-Authority Election Scheme](https://link.springer.com/content/pdf/10.1007/3-540-69053-0_9)        | Ronald Cramer, Rosario Gennaro, Berry Schoenmakers  |                                                                                     | This paper describes how El-Gamal was implemented in this repo                                                                                                                       |
| [Public-Key Cryptosystems Based on Composite Degree Residuosity Classes](https://link.springer.com/content/pdf/10.1007/3-540-48910-X_16.pdf)         | Pascal Paillier                                     | International conference on the theory and applications of cryptographic techniques | This paper is the original paper describing Paillier, which is how it is currently implemented as it has certain advantages over other variations                                    |

The work to create this repository was initially funded by the US NSF REU Site at FIU under the grant number REU CNS-1461119.  

## License
[MIT](https://choosealicense.com/licenses/mit/)

## Project status
The project is currently fully tested.
Currently, the stretch goal is to implement certificates using the Bouncy Castle API for these homomorphic encryption systems.
