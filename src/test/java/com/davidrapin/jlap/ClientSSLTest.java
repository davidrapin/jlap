package com.davidrapin.jlap;

import com.davidrapin.jlap.client.ClientPool;
import com.davidrapin.jlap.client.ConnectListener;
import com.davidrapin.jlap.client.NetLoc;
import com.davidrapin.jlap.ssl.SSLCertificate;
import io.netty.channel.nio.NioEventLoopGroup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

/**
 * Date: 04/06/13 at 01:24
 *
 * @author david
 */
public class ClientSSLTest
{
    private static final Logger log = LoggerFactory.getLogger(ClientSSLTest.class);

    @Test
    public void test() throws InterruptedException
    {
        ClientPool p = new ClientPool(new NioEventLoopGroup());
        NetLoc n = new NetLoc("www.google.fr", 443, true);
        p.connect(n, new ConnectListener()
        {
            @Override
            public void onSuccess(SSLCertificate certificate)
            {
                log.debug("> OK! cert : '" + certificate.chain[0].getSubjectX500Principal().toString() + "'");
            }

            @Override
            public void onFailure()
            {
                log.debug("failure");
            }
        });


        log.debug("end :)");
        Thread.sleep(20 * 1000);
        p.shutdownAll();
        log.debug("true end :))");
    }
}
