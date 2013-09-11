package com.davidrapin.jlap;

import com.davidrapin.jlap.client.HttpClient;
import com.davidrapin.jlap.client.HttpClientListener;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;

/**
 * Date: 19/05/13 at 19:20
 *
 * @author david
 */
@Test
public class ClientTest
{
    private static final Logger log = LoggerFactory.getLogger(ClientTest.class);

    public void test() throws URISyntaxException, MalformedURLException
    {
        HttpRequest r1 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/adsl/index.html");
        r1.headers().add("Host", "www.free.fr");

        HttpRequest r2 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/adsl/resiliez-votre-fai.html");
        r2.headers().add("Host", "www.free.fr");
//        HttpRequest r1 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://www.google.com/intl/en/about/");
//        HttpRequest r2 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://www.google.com/generate_204");

        HttpClientListener cl = new HttpClientListener()
        {
            @Override
            public void onServerCertificate(X509Certificate[] chain, String authType)
            {
                log.debug("CERTIFICATE>" + (chain != null && chain.length > 0 ? chain[0] : "none"));
            }

            @Override
            public void onConnected(HttpClient client)
            {

            }

            @Override
            public void onConnectionFailed(HttpClient client)
            {

            }

            @Override
            public void onConnectionClosed(HttpClient client)
            {

            }
        };

        HttpClient c = new HttpClient(cl, new NioEventLoopGroup(), "www.free.fr");

        c.request(r1, new ResponseListener("r1"));
        c.request(r2, new ResponseListener("r2"));
        c.waitForClose();
        log.debug("done :)");
    }


}
