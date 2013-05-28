package com.davidrapin.jlap.client;

import java.security.cert.X509Certificate;

/**
 * Date: 22/05/13 at 01:04
 *
 * @author david
 */
public interface HttpClientListener
{
    void onServerCertificate(X509Certificate[] chain, String authType);

    void onConnected(HttpClient client);

    void onConnectionClosed(HttpClient client);

    void onConnectionFailed(HttpClient client);
}
