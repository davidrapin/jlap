package com.davidrapin.jlap.ssl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import sun.security.x509.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Date: 28/05/13 at 00:06
 *
 * @author david
 */
public class SSLUtils
{
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


    /**
     * Create a self-signed X.509 Certificate
     *
     * @param dn        the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
     * @param pair      the KeyPair
     * @param days      how many days from now the Certificate is valid for
     * @param algorithm the signing algorithm, eg "SHA1withRSA"
     */
    public static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
        throws GeneralSecurityException, IOException
    {
        PrivateKey privateKey = pair.getPrivate();
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + days * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
        info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algorithmId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithmId));

        // Sign the cert to identify the algorithm that's used.
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privateKey, algorithm);

        // Update the algorithm, and resign.
        algorithmId = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algorithmId);
        cert = new X509CertImpl(info);
        cert.sign(privateKey, algorithm);

        return cert;
    }
}
