package com.davidrapin.jlap.client;

import com.davidrapin.jlap.ssl.SSLCertificate;

/**
 * Date: 04/06/13 at 00:49
 *
 * @author david
 */
public interface ConnectListener
{
    void onSuccess(SSLCertificate certificate);

    void onFailure();
}
