package com.davidrapin.jlap.ssl;

import com.davidrapin.jlap.client.HttpClientListener;
import com.davidrapin.jlap.client.NetLoc;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
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
    private static final Logger log = LoggerFactory.getLogger(SSLContextFactory.class);

    private static final String PROTOCOL = "TLS";
    private static final String SIGN_ALGORITHM = "SHA1withRSA";
    private static final String KEY_ALGORITHM = "RSA";
    private final ConcurrentMap<NetLoc, SSLContext> serverContextCache = new ConcurrentHashMap<NetLoc, SSLContext>();

    private final String caName;
    private final int caKeySize;
    private final int caDurationDays;
    private final String caP12Path;
    private final String caPemPath;
    private final char[] caKeyStorePassword;

    private final int fakeCertKeySize;
    private final int fakeCertDurationDays;
    private final char[] fakeKeyStorePassword;

    // System.currentTimeMillis() + durationDays * (1000L * 60 * 60 * 24)

    public SSLContextFactory(
        String caName, int caKeySize, int caDurationDays, String caP12Path, String caPemPath, String caKeyStorePassword,
        int fakeCertKeySize, int fakeCertDurationDays, String fakeKeyStorePassword
    )
    {
        this.caName = caName;
        this.caKeySize = caKeySize;
        this.caDurationDays = caDurationDays;
        this.caP12Path = caP12Path;
        this.caPemPath = caPemPath;
        this.caKeyStorePassword = caKeyStorePassword.toCharArray();

        this.fakeCertKeySize = fakeCertKeySize;
        this.fakeCertDurationDays = fakeCertDurationDays;
        this.fakeKeyStorePassword = fakeKeyStorePassword.toCharArray();
    }

    public SSLContextFactory()
    {
        this(
            "CN=ZProxy Authority, O=ZProxy", 1024, 12 * 31, "./ca-cert.p12", "./ca-cert.pem", "hihahou",
            1024, 12 * 31, "fakeKeyStorePass"
        );
    }

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

    public SSLContext getServerContext(NetLoc server, SSLCertificate realServerCertificate)
    {
        // fix x500 name
        String x500Name = realServerCertificate.chain[0].getSubjectX500Principal().toString();
        x500Name = x500Name.replaceAll("CN=[^,]+", "CN=" + server.host);

        return getServerContext(server, x500Name);
    }

    public SSLContext getServerContext(NetLoc server, String realX500Name)
    {
        try
        {
            return getServerContext0(server, realX500Name);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     *
     * @param server   the server that this certificate is generated for
     * @param x500Name the X500 name of the real server certificate
     * @return a JKS KeyStore containing a fake certificate for this server, signed by our CA.
     */
    private SSLContext getServerContext0(NetLoc server, String x500Name)
        throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException,
               InvalidKeyException, SignatureException, NoSuchProviderException, KeyStoreException,
               KeyManagementException
    {
        SSLContext serverContext = serverContextCache.get(server);
        if (serverContext == null) serverContext = createServerContext(server, x500Name);
        return serverContext;
    }

    public synchronized SSLContext createServerContext(NetLoc server, String x500name)
        throws CertificateException, NoSuchAlgorithmException, KeyStoreException, SignatureException,
               NoSuchProviderException, InvalidKeyException, IOException, UnrecoverableKeyException,
               KeyManagementException
    {
        log.info("generating fake cert for '{}'", x500name);

        // get or create a Certificate Authority
        KeyStore caKeyStore = getCaKeyStore();

        // generate fake certificate
        KeyPair fakeCertKeyPair = KeyGenerator.generaKeyPair(fakeCertKeySize, KEY_ALGORITHM);
        PKCS10CertificationRequest request = SSLUtils.createCertificationRequest(
            x500name, SIGN_ALGORITHM, fakeCertKeyPair
        );
        X509Certificate[] fakeCertChain = SSLUtils.signCertificationRequest(
            request, fakeCertDurationDays, SIGN_ALGORITHM, caKeyStore, caKeyStorePassword
        );

        // store fake certificate in a JKS keyStore
        KeyStore fakeCertKeyStore = KeyStore.getInstance("JKS");
        fakeCertKeyStore.load(null, null);
        fakeCertKeyStore.setKeyEntry("key1", fakeCertKeyPair.getPrivate(), fakeKeyStorePassword, fakeCertChain);

        // create a SSL context that uses this keyStore
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(fakeCertKeyStore, fakeKeyStorePassword);
        SSLContext serverContext = SSLContext.getInstance(PROTOCOL);
        serverContext.init(keyManagerFactory.getKeyManagers(), null, null);

        // cache the SSL context
        serverContextCache.put(server, serverContext);

        return serverContext;
    }

    private KeyStore getCaKeyStore()
        throws CertificateException, NoSuchAlgorithmException, KeyStoreException, SignatureException,
               NoSuchProviderException, InvalidKeyException, IOException
    {
        File p12File = new File(caP12Path);
        KeyStore caKeyStore;
        if (!p12File.exists())
        {
            // create new CA
            caKeyStore = SSLUtils.createCaKeyStore(caName, KEY_ALGORITHM, SIGN_ALGORITHM, caKeySize, caDurationDays);

            // save the CA certificate
            FileOutputStream out = new FileOutputStream(p12File);
            caKeyStore.store(out, caKeyStorePassword);
            out.close();

            // save the newly created CA KeyStore to
            PEMWriter pw = new PEMWriter(new FileWriter(caPemPath));
            pw.writeObject(caKeyStore.getCertificate("CA"));
            pw.close();
        }
        else
        {
            // load key store
            caKeyStore = KeyStore.getInstance("PKCS12");
            caKeyStore.load(new FileInputStream(p12File), caKeyStorePassword);
        }
        return caKeyStore;
    }
}
