package com.davidrapin.jlap;

import com.davidrapin.jlap.client.NetLoc;
import com.davidrapin.jlap.ssl.SSLContextFactory;
import org.testng.annotations.Test;

/**
 * Date: 04/06/13 at 01:38
 *
 * @author david
 */
public class SSLTest
{
    @Test
    public void test()
    {
        SSLContextFactory.createServerContext(
            new NetLoc("www.google.fr", 443, true),
            "CN=google.com, O=Google Inc, ST=California, C=US"
        );
    }
}
