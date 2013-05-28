package com.davidrapin.jlap.proxy;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelOption;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;

/**
 * Date: 07/03/13
 * Time: 14:40
 *
 * @author drapin
 */
public class HttpProxy
{
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
            // config
            bootstrap
                .group(new NioEventLoopGroup())
                .channel(NioServerSocketChannel.class)
                .childOption(ChannelOption.TCP_NODELAY, true)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .localAddress("0.0.0.0", port)
                .childHandler(new HttpProxyChannelInitializer())
            ;

            // bind
            Channel channel = bootstrap.bind().sync().channel();

            // listen to close
            System.out.println("> before closeFuture");
            channel.closeFuture().addListener(new ChannelFutureListener()
            {
                @Override
                public void operationComplete(ChannelFuture future) throws Exception
                {
                    System.out.println("> in closeFuture");
                    future.channel().close();
                }
            }).sync();


        }
        finally
        {
            System.out.println("> before shutdown");
            bootstrap.shutdown();
            System.out.println("> after shutdown");
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
