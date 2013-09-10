package com.davidrapin.jlap;

import com.davidrapin.jlap.client.ClientPool;
import com.davidrapin.jlap.client.ConnectListener;
import com.davidrapin.jlap.client.NetLoc;
import com.davidrapin.jlap.ssl.SSLCertificate;
import io.netty.channel.nio.NioEventLoopGroup;
import org.testng.annotations.Test;

/**
 * Date: 04/06/13 at 01:24
 *
 * @author david
 */
public class ClientSSLTest
{
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
                System.out.println("> OK! cert : '" + certificate.chain[0].getSubjectX500Principal().toString() + "'");
            }

            @Override
            public void onFailure()
            {
                System.out.println("failure");
            }
        });


        System.out.println("end :)");
        Thread.sleep(20*1000);
        p.shutdown();
        System.out.println("true end :))");
    }
}
