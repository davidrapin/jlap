package com.davidrapin.jlap.ssl;

import java.security.cert.X509Certificate;

/**
 * Date: 27/05/13 at 23:37
 *
 * @author david
 */
public class SSLCertificate
{
    public final X509Certificate[] chain;
    public final String authType;

    public SSLCertificate(X509Certificate[] chain, String authType)
    {
        this.chain = chain;
        this.authType = authType;
    }
}
