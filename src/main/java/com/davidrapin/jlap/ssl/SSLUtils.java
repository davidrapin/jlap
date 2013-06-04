package com.davidrapin.jlap.ssl;

import es.sing.util.KeyGenerator;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

/**
 * Date: 28/05/13 at 00:06
 *
 * @author david
 */
public class SSLUtils
{
    //private static final X509V3CertificateGenerator V3_CERTIFICATE_GENERATOR = ;

    static
    {
        //Security.addProvider(new BouncyCastleProvider());
        Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }

    /**
     * @param xName            an X509 Name
     * @param keyPairAlgorithm something like RSA / DSA / DH
     * @param signAlgorithm    something like SHA1withDSA / SHA1withRSA / DSA / SHA512withRSA / SHA1withDSA
     * @param caKeySize        the key size in bytes (1024 would be good)
     * @param validityMonths   the number of month this certificate will be valid, starting now
     * @return a KeyStore containing the generated certificate with its private key.
     * @throws Exception
     */
    public static KeyStore createCaKeyStore(
        String xName, String keyPairAlgorithm, String signAlgorithm, int caKeySize, int validityMonths
    ) throws Exception
    {
        // generate keyPair
        KeyPair caKeyPair = KeyGenerator.generaKeyPair(caKeySize, keyPairAlgorithm);
        PrivateKey caPrivateKey = caKeyPair.getPrivate();
        PublicKey caPublicKey = caKeyPair.getPublic();

        X509Certificate caCertificate = createCA(caPublicKey, caPrivateKey, xName, validityMonths, signAlgorithm);

        return createCaKeyStore(caCertificate, caPrivateKey);
    }

    /**
     * @param caCertificate a CA certificate
     * @param caPrivateKey  a CA private key
     * @return a PKCS12 KeyStore for the given CA certificate and private key.
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws KeyStoreException
     */
    public static KeyStore createCaKeyStore(X509Certificate caCertificate, PrivateKey caPrivateKey)
        throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException
    {
        java.security.cert.Certificate[] certificates = new java.security.cert.Certificate[2];
        certificates[1] = caCertificate;
        certificates[0] = caCertificate;
        KeyStore caKeyStore = KeyStore.getInstance("PKCS12");
        caKeyStore.load(null, null);
        caKeyStore.setCertificateEntry("CA", caCertificate);
        caKeyStore.setKeyEntry("CApriv", caPrivateKey, null, certificates);
        return caKeyStore;
    }


    public static X509Certificate createCA(
        PublicKey publicKey, PrivateKey privateKey, String xName, int durationMonths, String signAlgorithm
    ) throws Exception
    {
        X509Principal authorityDN = new X509Principal(xName);

        // reset certificate generator
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        //certGen.reset();

        // create CA certificate
        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(authorityDN);

        // set the validity interval (start now)
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(
            System.currentTimeMillis() + durationMonths * (1000L * 60 * 60 * 24 * 30)
        ));

        certGen.setSubjectDN(authorityDN);
        certGen.setPublicKey(publicKey);
        certGen.setSignatureAlgorithm(signAlgorithm);

        certGen.addExtension(
            X509Extensions.SubjectKeyIdentifier,
            false,
            createSubjectKeyId(publicKey)
        );

        certGen.addExtension(
            X509Extensions.AuthorityKeyIdentifier,
            false,
            createAuthorityKeyId(publicKey)
        );

        certGen.addExtension(
            X509Extensions.BasicConstraints,
            false,
            new BasicConstraints(true)
        );

        certGen.addExtension(
            X509Extensions.KeyUsage,
            false,
            new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign)
        );

        X509Certificate cert = certGen.generate(privateKey);

        cert.checkValidity(new Date());
        cert.verify(publicKey);

        return cert;
    }

    public static SubjectKeyIdentifier createSubjectKeyId(PublicKey pubKey)
    {
        try
        {
            ByteArrayInputStream bIn = new ByteArrayInputStream(pubKey.getEncoded());
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
                (ASN1Sequence) new ASN1InputStream(bIn).readObject()
            );
            return new SubjectKeyIdentifier(info);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    public static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey pubKey)
    {
        try
        {
            ByteArrayInputStream keyBytes = new ByteArrayInputStream(pubKey.getEncoded());
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
                (ASN1Sequence) new ASN1InputStream(keyBytes).readObject()
            );
            return new AuthorityKeyIdentifier(info);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    /*public static PKCS10CertificationRequest createCertificationRequest(
        String xName, String keyPairAlgorithm, String signAlgorithm, int keySize
    ) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        return createCertificationRequest(
            xName,
            signAlgorithm,
            KeyGenerator.generaKeyPair(keySize, keyPairAlgorithm)
        );
    }*/

    public static PKCS10CertificationRequest createCertificationRequest(
        String xName, String signAlgorithm, KeyPair keyPair
    ) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException
    {
        return new PKCS10CertificationRequest(
            signAlgorithm,
            new X509Name(xName),
            keyPair.getPublic(),
            new DERSet(),
            keyPair.getPrivate()
        );
    }

    /**
     * found at:
     * http://www.java2s.com/Tutorial/Java/0490__Security/CreatingaCertificatefromaCertificationRequest.htm
     *
     * @param request       the certification request
     * @param caCertificate the CA certificate
     * @param caPrivateKey  the CA private keys
     * @return a now keychain
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws CertificateParsingException
     * @throws SignatureException
     * @throws CertificateEncodingException
     */
    public static X509Certificate[] signCertificationRequest(
        PKCS10CertificationRequest request, X509Certificate caCertificate, PrivateKey caPrivateKey
    ) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
             CertificateParsingException, SignatureException, CertificateEncodingException
    {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(caCertificate.getSubjectX500Principal());
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 10000));
        certGen.setSubjectDN(request.getCertificationRequestInfo().getSubject());
        certGen.setPublicKey(request.getPublicKey());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        certGen.addExtension(
            X509Extensions.AuthorityKeyIdentifier,
            false,
            new AuthorityKeyIdentifierStructure(caCertificate)
        );

        certGen.addExtension(
            X509Extensions.SubjectKeyIdentifier,
            false,
            new SubjectKeyIdentifierStructure(request.getPublicKey())
        );

        certGen.addExtension(
            X509Extensions.BasicConstraints,
            true,
            new BasicConstraints(false)
        );

        certGen.addExtension(
            X509Extensions.KeyUsage,
            true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
        );

        certGen.addExtension(
            X509Extensions.ExtendedKeyUsage,
            true,
            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
        );

        ASN1Set attributes = request.getCertificationRequestInfo().getAttributes();
        for (int i = 0; i != attributes.size(); i++)
        {
            Attribute attr = Attribute.getInstance(attributes.getObjectAt(i));

            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest))
            {
                X509Extensions extensions = X509Extensions.getInstance(attr.getAttrValues().getObjectAt(0));

                Enumeration e = extensions.oids();
                while (e.hasMoreElements())
                {
                    DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                    X509Extension ext = extensions.getExtension(oid);
                    certGen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
                }
            }
        }
        X509Certificate issuedCert = certGen.generate(caPrivateKey);

        return new X509Certificate[]{issuedCert, caCertificate};
    }

    public static X509Certificate[] signCertificationRequest(PKCS10CertificationRequest request, KeyStore caKeyStore, String caKeyStorePassword)
        throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateEncodingException,
               SignatureException, NoSuchProviderException, InvalidKeyException, CertificateParsingException
    {
        return signCertificationRequest(
            request,
            (X509Certificate) caKeyStore.getCertificate("CApriv"),
            (PrivateKey) caKeyStore.getKey("CApriv", caKeyStorePassword.toCharArray())
        );
    }


    /*
    public static void testKeyPair(KeyPair keyPair) throws Exception
     {
         Security.addProvider(new BouncyCastleProvider());

         String message = "hello world";
         //File privateKey = new File("private.pem");
         //KeyPair keyPair = readKeyPair(privateKey, "password".toCharArray());

         // encode with private key
         Signature signature = Signature.getInstance("SHA256WithRSAEncryption");
         signature.initSign(keyPair.getPrivate());
         signature.update(message.getBytes());
         byte[] signatureBytes = signature.sign();
         System.out.println(new String(Hex.encode(signatureBytes)));

         // decode with public key
         Signature verifier = Signature.getInstance("SHA256WithRSAEncryption");
         verifier.initVerify(keyPair.getPublic());
         verifier.update(message.getBytes());
         if (verifier.verify(signatureBytes))
         {
             System.out.println("Signature is valid");
         }
         else
         {
             System.out.println("Signature is invalid");
         }
     }
    */

    /*
    private static final class DefaultPasswordFinder implements PasswordFinder
    {
        private String password;

        private DefaultPasswordFinder(String password)
        {
            this.password = password;
        }

        @Override
        public char[] getPassword()
        {
            return password.toCharArray();
        }
    }


    public static KeyPair getKeyPair(InputStream publicKeyPem, InputStream privateKeyPem, final String password) throws IOException
    {
        Security.addProvider(new BouncyCastleProvider());
        //, new DefaultPasswordFinder(password)
        PEMReader r = new PEMReader(new InputStreamReader(publicKeyPem));
        Object keyPair = r.readObject();
        System.out.println(">" + keyPair);
        return (KeyPair) keyPair;
    }
    public static void main(String[] args) throws IOException
    {
        //PKCS8EncodedKeySpec s = new PKCS8EncodedKeySpec();


        getKeyPair(
            SSLUtils.class.getResourceAsStream("ca_certificate.pem"),
            SSLUtils.class.getResourceAsStream("ca_private.pem"),
            "jlap"
        );
    }
    */

    /*

    private KeyPair readPrivateKey(InputStream privateKeyPem) throws IOException
    {
        byte[] keyBytes = readKeyBytes(privateKeyPem);
        keyBytes = PEMUtilities.crypt(false, provider, keyBytes, password, dekAlgName, iv);



            KeySpec pubSpec, privSpec;
            ByteArrayInputStream bIn = new ByteArrayInputStream(keyBytes);
            ASN1InputStream aIn = new ASN1InputStream(bIn);
            ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

            if (type.equals("RSA"))
            {
                DERInteger v = (DERInteger)seq.getObjectAt(0);
                DERInteger              mod = (DERInteger)seq.getObjectAt(1);
                DERInteger              pubExp = (DERInteger)seq.getObjectAt(2);
                DERInteger              privExp = (DERInteger)seq.getObjectAt(3);
                DERInteger              p1 = (DERInteger)seq.getObjectAt(4);
                DERInteger              p2 = (DERInteger)seq.getObjectAt(5);
                DERInteger              exp1 = (DERInteger)seq.getObjectAt(6);
                DERInteger              exp2 = (DERInteger)seq.getObjectAt(7);
                DERInteger              crtCoef = (DERInteger)seq.getObjectAt(8);

                pubSpec = new RSAPublicKeySpec(
                            mod.getValue(), pubExp.getValue());
                privSpec = new RSAPrivateCrtKeySpec(
                        mod.getValue(), pubExp.getValue(), privExp.getValue(),
                        p1.getValue(), p2.getValue(),
                        exp1.getValue(), exp2.getValue(),
                        crtCoef.getValue());
            }
            else    // "DSA"
            {
                DERInteger              v = (DERInteger)seq.getObjectAt(0);
                DERInteger              p = (DERInteger)seq.getObjectAt(1);
                DERInteger              q = (DERInteger)seq.getObjectAt(2);
                DERInteger              g = (DERInteger)seq.getObjectAt(3);
                DERInteger              y = (DERInteger)seq.getObjectAt(4);
                DERInteger              x = (DERInteger)seq.getObjectAt(5);

                privSpec = new DSAPrivateKeySpec(
                            x.getValue(), p.getValue(),
                                q.getValue(), g.getValue());
                pubSpec = new DSAPublicKeySpec(
                            y.getValue(), p.getValue(),
                                q.getValue(), g.getValue());
            }

            KeyFactory          fact = KeyFactory.getInstance(type, provider);

            return new KeyPair(
                        fact.generatePublic(pubSpec),
                        fact.generatePrivate(privSpec));
    }
    */

    /*
    private byte[] readKeyBytes(InputStream input) throws IOException
    {
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        StringBuilder key = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null)
        {
            if (line.startsWith("-----")) continue;
            key.append(line.trim());
        }
        return Base64.decode(key.toString());
    }
*/

//
//    /**
//     * Create a self-signed X.509 Certificate
//     *
//     * @param dn        the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
//     * @param pair      the KeyPair
//     * @param days      how many days from now the Certificate is valid for
//     * @param algorithm the signing algorithm, eg "SHA1withRSA"
//     */
//    public static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
//        throws GeneralSecurityException, IOException
//    {
//        PrivateKey privateKey = pair.getPrivate();
//        X509CertInfo info = new X509CertInfo();
//        Date from = new Date();
//        Date to = new Date(from.getTime() + days * 86400000l);
//        CertificateValidity interval = new CertificateValidity(from, to);
//        BigInteger sn = new BigInteger(64, new SecureRandom());
//        X500Name owner = new X500Name(dn);
//
//        info.set(X509CertInfo.VALIDITY, interval);
//        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
//        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
//        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
//        info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
//        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
//        AlgorithmId algorithmId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
//        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithmId));
//
//        // Sign the cert to identify the algorithm that's used.
//        X509CertImpl cert = new X509CertImpl(info);
//        cert.sign(privateKey, algorithm);
//
//        // Update the algorithm, and resign.
//        algorithmId = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
//        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algorithmId);
//        cert = new X509CertImpl(info);
//        cert.sign(privateKey, algorithm);
//
//        return cert;
//    }
//


//
//    public X509Certificate generateCert() throws NoSuchProviderException, NoSuchAlgorithmException
//    {
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
//        keyPairGenerator.initialize(1024, new SecureRandom());
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//
//        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
//        X500Principal dnName = new X500Principal("CN=Sergey");
//        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
//        certGen.setSubjectDN(dnName);
//        certGen.setIssuerDN(caCert.getSubjectX500Principal());
//        certGen.setNotBefore(validityBeginDate);
//        certGen.setNotAfter(validityEndDate);
//        certGen.setPublicKey(keyPair.getPublic());
//        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
//
//        certGen.addExtension(
//            X509Extensions.AuthorityKeyIdentifier,
//            false,
//            new AuthorityKeyIdentifierStructure(caCert)
//        );
//        certGen.addExtension(
//            X509Extensions.SubjectKeyIdentifier,
//            false,
//            new SubjectKeyIdentifierStructure(keyPair.getPublic())
//        );
//
//        X509Certificate cert = certGen.generate(caCertPrivateKey, "BC");
//    }

}
