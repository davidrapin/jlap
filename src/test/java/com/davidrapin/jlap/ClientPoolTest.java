package com.davidrapin.jlap;

import com.davidrapin.jlap.client.ClientPool;
import com.davidrapin.jlap.client.NetLoc;
import com.davidrapin.jlap.ssl.SSLCertificate;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpVersion;
import org.testng.annotations.Test;

/**
 * Date: 22/05/13 at 02:36
 *
 * @author david
 */
@Test
public class ClientPoolTest
{
    public void test() throws InterruptedException
    {
        ClientPool p1 = new ClientPool();
        ClientPool p2 = new ClientPool();

        HttpRequest r1 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/adsl/index.html");
        r1.headers().add("Host", "www.free.fr");

        HttpRequest r2 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/adsl/resiliez-votre-fai.html");
        r2.headers().add("Host", "www.free.fr");

        HttpRequest r3 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/intl/en/about/");
        r3.headers().add("Host", "www.google.com");

        HttpRequest r4 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/generate_204");
        r4.headers().add("Host", "www.google.com");

        p1.sendRequest(r1, new ResponseListener("r1"));
        p1.sendRequest(r3, new ResponseListener("r3"));
        p1.sendRequest(r2, new ResponseListener("r2"));
        p2.sendRequest(r4, new ResponseListener("r4"));

        Thread.sleep(500000);
    }

    public void test2() throws InterruptedException
    {
        final ClientPool p = new ClientPool();

        final HttpRequest r1 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "https://www.google.fr/");
        r1.headers().add("Host", "www.google.fr");
        final NetLoc n = NetLoc.forRequest(r1);

        p.sendRequest(r1, new ResponseListener("r1"));

        System.out.println("end :)");
        Thread.sleep(500000);
        System.out.println("true end :))");
    }


}
