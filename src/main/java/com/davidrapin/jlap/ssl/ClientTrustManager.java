package com.davidrapin.jlap.ssl;

import com.davidrapin.jlap.client.HttpClientListener;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Date: 27/05/13 at 23:05
 *
 * @author david
 */
public class ClientTrustManager extends DummyTrustManager
{
    private final HttpClientListener listener;

    public ClientTrustManager(HttpClientListener listener)
    {
        this.listener = listener;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
        listener.onServerCertificate(chain, authType);
    }
}
