#!/bin/bash
# Used for Signing JAR files.
# In this case, it is to allow importing Paillier/DGK Library
# https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/HowToImplAProvider.html#Step61

# Step 1
keytool -genkeypair -alias <alias> -keyalg DSA -keysize 1024 -dname "cn=<Company Name>, ou=Java Software Code Signing, o=Sun Microsystems Inc" -keystore <keystore file name> -storepass <keystore password>

# Step 2
keytool -certreq -alias <alias> -file <csr file name> -keystore <keystore file name> -storepass <keystore password>

# Step 3, Contact CSR
# Step 4 

# Step 5
keytool -import -alias <alias for the CA cert> -file <CA cert file name> -keystore <keystore file name> -storepass <keystore password>
keytool -import -alias <alias> -file <code-signing cert file name> -keystore <keystore file name> -storepass <keystore password>

jarsigner -keystore <keystore file name> -storepass <keystore password> <JAR file name> <alias>
jarsigner -verify <JAR file name> 