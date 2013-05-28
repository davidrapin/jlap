package com.davidrapin.jlap.ssl;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Date: 27/05/13 at 22:39
 *
 * @author david
 */
public class DummyTrustManager implements X509TrustManager
{
    @Override
    public X509Certificate[] getAcceptedIssuers()
    {
        return new X509Certificate[0];
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
        // Always trust
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
        // Always trust
    }
}
