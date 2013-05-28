package com.davidrapin.jlap.ssl;

import com.davidrapin.jlap.client.HttpClientListener;
import io.netty.example.securechat.SecureChatKeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.security.KeyStore;
import java.security.Security;

/**
 * Date: 27/05/13 at 23:10
 *
 * @author david
 */
public class SSLContextFactory
{
    private static final String PROTOCOL = "TLS";
    private static final SSLContext SERVER_CONTEXT = createServerContext();

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

//    public static SSLContext getClientContext()
//    {
//        return CLIENT_CONTEXT;
//    }
//
//    private static final SSLContext CLIENT_CONTEXT = createClientContext();

//    private static SSLContext createClientContext()
//    {
//        try
//        {
//            SSLContext clientContext = SSLContext.getInstance(PROTOCOL);
//            clientContext.init(null, TrustManagerFactory.getTrustManagers(), null);
//            return clientContext;
//        }
//        catch (Exception e)
//        {
//            throw new RuntimeException("could not generate SSL client context", e);
//
//        }
//    }


    public static SSLContext getServerContext()
    {
        return SERVER_CONTEXT;
    }


    private static SSLContext createServerContext()
    {
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
}
