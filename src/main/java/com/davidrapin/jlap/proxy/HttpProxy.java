package com.davidrapin.jlap.proxy;

import com.davidrapin.jlap.ssl.SSLContextFactory;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelOption;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Date: 07/03/13
 * Time: 14:40
 *
 * @author drapin
 */
public class HttpProxy
{
    private static final Logger log = LoggerFactory.getLogger(HttpProxy.class);
    
    private final int port;

    public HttpProxy(int port)
    {
        this.port = port;
    }

    public void run() throws Exception
    {
        ServerBootstrap bootstrap = new ServerBootstrap();

        try
        {
            // ssl context factory
            SSLContextFactory sslContextFactory = new SSLContextFactory();

            // config
            bootstrap
                .group(new NioEventLoopGroup())
                .channel(NioServerSocketChannel.class)
                .childOption(ChannelOption.TCP_NODELAY, true)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .localAddress("0.0.0.0", port)
                .childHandler(new HttpProxyChannelInitializer(sslContextFactory))
            ;

            // bind
            Channel channel = bootstrap.bind().sync().channel();

            // listen to close
            log.debug("before closeFuture");
            channel.closeFuture().addListener(new ChannelFutureListener()
            {
                @Override
                public void operationComplete(ChannelFuture future) throws Exception
                {
                    log.debug("in closeFuture");
                    future.channel().close();
                }
            }).sync();


        }
        finally
        {
            log.debug("before shutdown");
            bootstrap.shutdown();
            log.debug("after shutdown");
        }
    }

    /*
    private SSLEngine createSSLEngine()
    {
        char[] passPhrase = "snoopy".toCharArray();

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
//            KeyStore trustStore = KeyStore.getInstance("JKS");

            keyStore.load(getClass().getResourceAsStream("mitm-cert.jks"), passPhrase);
//            trustStore.load(new FileInputStream(trustStoreFile), passPhrase);

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, passPhrase);

//            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
//            trustManagerFactory.init(trustStore);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(
                keyManagerFactory.getKeyManagers(),
                null,// trustManagerFactory.getTrustManagers(),
                null
            );


            SSLEngine serverEngine = context.createSSLEngine();
            serverEngine.setUseClientMode(false);
            serverEngine.setEnableSessionCreation(true);
            //serverEngine.setWantClientAuth(true);

            return serverEngine;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
*/

}
