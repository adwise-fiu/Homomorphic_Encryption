package security.generic;

/*
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
*/

// Based off: https://stackoverflow.com/questions/24084206/java-generate-certificate-x509certificate-object-from-privatekey-object

// Other useful links used
// http://techxperiment.blogspot.com/2016/10/create-and-read-pkcs-8-format-private.html
// https://techxperiment.blogspot.com/2016/10/create-version-3-x509-certificate.html
public class CertBuilder
{
	/*
    public static void main(String[] args) throws Exception 
    {
        // Generate a keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        JcaX509v3CertificateBuilder x509Builder = x509Builder(kp.getPublic());
        
        // Create a signer to sign (self-sign) the certificate.
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256WITHRSA");
        ContentSigner signer = signerBuilder.build(kp.getPrivate());

        // Now finish the creation of the self-signed certificate.
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate mySelfSignedCert = converter.getCertificate(x509Builder.build(signer));

        // Now create a KeyStore and store the private key and associated cert.
        final char [] password = "password99".toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, password);

        KeyStore.PrivateKeyEntry privKeyEntry = new KeyStore.PrivateKeyEntry(kp.getPrivate(), 
                new Certificate[] {mySelfSignedCert});
        ks.setEntry("myRSAkey", privKeyEntry, new KeyStore.PasswordProtection(password));

        // Now save off the KeyStore to a file.
        FileOutputStream fos = null;
        try 
        {
            fos = new FileOutputStream("MyKeys.jks");
            ks.store(fos, password);
        } 
        finally 
        {
            if (fos != null) 
            {
                fos.close();
            }
        }
    }
    
    // Start creating a self-signed X.509 certificate with the public key
    public static JcaX509v3CertificateBuilder x509Builder(PublicKey key)
    {
        X500Name subjName = new X500Name("C=US, ST=NY, O=Certs_R_Us, CN=notreal@example.com");
        BigInteger serialNumber = new BigInteger("900");
        Calendar cal = Calendar.getInstance();
        cal.set(2014, 6, 7, 11, 59, 59);
        Date notBefore = cal.getTime();
        cal.add(Calendar.YEAR, 10); // Expires in 10 years
        Date notAfter = cal.getTime();
        JcaX509v3CertificateBuilder x509Builder = new JcaX509v3CertificateBuilder(subjName,
        		serialNumber, notBefore, notAfter, subjName, key);
        return x509Builder;
    }
    */
}