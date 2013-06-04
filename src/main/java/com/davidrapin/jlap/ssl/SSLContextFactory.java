package com.davidrapin.jlap.ssl;

import com.davidrapin.jlap.client.HttpClientListener;
import com.davidrapin.jlap.client.NetLoc;
import es.sing.util.KeyGenerator;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Date: 27/05/13 at 23:10
 *
 * @author david
 */
public class SSLContextFactory
{
    private static final String PROTOCOL = "TLS";
    private static final SSLContext SERVER_CONTEXT = createServerContext_JKS();
    private static final ConcurrentMap<NetLoc, KeyStore> FAKE_CERTIFICATES = new ConcurrentHashMap<NetLoc, KeyStore>();

    public static SSLContext getClientContext(HttpClientListener listener)
    {
        try
        {
            SSLContext clientContext = SSLContext.getInstance(PROTOCOL);
            clientContext.init(null, TrustManagerFactory.getTrustManagers(listener), null);
            return clientContext;
        }
        catch (Exception e)
        {
            throw new RuntimeException("could not generate SSL client context", e);

        }
    }

    public static SSLContext getServerContext() throws Exception
    {
        return SERVER_CONTEXT;
    }


    private static SSLContext createServerContext_JKS()
    {
        // SunX509
        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        if (algorithm == null) algorithm = "SunX509";

        SSLContext serverContext;
        try
        {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(SSLContextFactory.class.getResourceAsStream("jlap.jks"), "jlap!!".toCharArray());


            // Set up key manager factory to use our key store
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(ks, "jlap!!".toCharArray());

            // Initialize the SSLContext to work with our key managers.
            serverContext = SSLContext.getInstance(PROTOCOL);
            serverContext.init(kmf.getKeyManagers(), null, null);
            return serverContext;
        }
        catch (Exception e)
        {
            throw new Error("Failed to initialize the server-side SSLContext", e);
        }
    }

    public static SSLContext createServerContext(NetLoc server, SSLCertificate serverCertificate)
    {
        return createServerContext(
            server,
            serverCertificate.chain[0].getSubjectX500Principal().toString()
        );
    }

    public static SSLContext createServerContext(NetLoc server, String certificateName)
    {
        try
        {
            String p12Path = "./ca-cert.p12";
            String pemPath = "./ca-cert.pem";
            File p12File = new File(p12Path);
            String caKeyStorePassword = "hihahou";
            String defaultKeyStorePassword = "lulz";

            KeyStore caKeyStore;
            if (!p12File.exists())
            {
                // create new CA
                caKeyStore = SSLUtils.createCaKeyStore("CN=zzz.com, O=ZZZ, ST=FR", "RSA", "SHA1withRSA", 1024, 12);
                FileOutputStream out = new FileOutputStream(p12File);
                caKeyStore.store(out, caKeyStorePassword.toCharArray());
                out.close();

                PEMWriter pw = new PEMWriter(new FileWriter(pemPath));
                pw.writeObject(caKeyStore.getCertificate("CA"));
                pw.close();
            }
            else
            {
                // load key store
                caKeyStore = KeyStore.getInstance("PKCS12");
                caKeyStore.load(new FileInputStream(p12File), caKeyStorePassword.toCharArray());
            }

            KeyStore fakeCertKeyStore = FAKE_CERTIFICATES.get(server);
            if (fakeCertKeyStore == null)
            {
                KeyPair keyPair = KeyGenerator.generaKeyPair(1024, "RSA");
                PKCS10CertificationRequest certificationRequest = SSLUtils.createCertificationRequest(certificateName, "SHA1withRSA", keyPair);
                X509Certificate[] certificates = SSLUtils.signCertificationRequest(certificationRequest, caKeyStore, caKeyStorePassword);
                fakeCertKeyStore = KeyStore.getInstance("JKS");
                fakeCertKeyStore.load(null, null);
                fakeCertKeyStore.setKeyEntry("key1", keyPair.getPrivate(), defaultKeyStorePassword.toCharArray(), certificates);
                FAKE_CERTIFICATES.put(server, fakeCertKeyStore);
            }

            // Initialize the SSLContext to work with our key managers.
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(fakeCertKeyStore, defaultKeyStorePassword.toCharArray());
            SSLContext serverContext = SSLContext.getInstance(PROTOCOL);
            serverContext.init(kmf.getKeyManagers(), null, null);
            return serverContext;
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }
}
