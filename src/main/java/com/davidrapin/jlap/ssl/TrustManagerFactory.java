package com.davidrapin.jlap.ssl;

import com.davidrapin.jlap.client.HttpClientListener;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * Date: 24/05/13 at 22:05
 *
 * @author david
 */
public class TrustManagerFactory extends TrustManagerFactorySpi
{
    private static final TrustManager DUMMY_TRUST_MANAGER = new DummyTrustManager();

    public static TrustManager[] getTrustManagers()
    {
        return new TrustManager[]{DUMMY_TRUST_MANAGER};
    }

    public static TrustManager[] getTrustManagers(HttpClientListener listener)
    {
        return new TrustManager[]{new ClientTrustManager(listener)};
    }

    @Override
    protected TrustManager[] engineGetTrustManagers()
    {
        return getTrustManagers();
    }

    @Override
    protected void engineInit(KeyStore keystore) throws KeyStoreException
    { }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters)
        throws InvalidAlgorithmParameterException
    { }
}
