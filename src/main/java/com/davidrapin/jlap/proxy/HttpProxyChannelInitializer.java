package com.davidrapin.jlap.proxy;

import com.davidrapin.jlap.client.ClientPool;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;

/**
 * Date: 03/05/13 at 00:29
 *
 * @author david
 */
public class HttpProxyChannelInitializer extends ChannelInitializer<SocketChannel>
{
    private ClientPool clientPool;

    @Override
    public void initChannel(SocketChannel ch) throws Exception
    {
        // Create a default pipeline implementation.
        ChannelPipeline p = ch.pipeline();

        if (clientPool == null)
        {
            clientPool = new ClientPool(ch.eventLoop());
        }

        p.addLast("http-decoder", new HttpRequestDecoder());

        // if you don't want to handle HttpChunks.
        p.addLast("http-aggregator", new HttpObjectAggregator(1024 * 1024));

        p.addLast("http-proxy", new HttpProxyHandler(clientPool));

        //p.addLast("zipper", new HttpContentCompressor());

        p.addLast("http-encoder", new HttpResponseEncoder()
        {
//            @Override
//            public boolean acceptOutboundMessage(Object msg) throws Exception
//            {
//                boolean accept = super.acceptOutboundMessage(msg);
//                System.out.println("ENCODER accept:_" + accept + "_ (" + msg.getClass() + ")");
//                return accept;
//            }
        });

        //p.addLast("logger", new LoggingHandler());
    }


    // SSLEngine engine = createSSLEngine();
    // SslHandler httpsHandler = new HTTPSHandler(Proxy.this, engine);
    // p.addLast("https", httpsHandler);

    // Uncomment the following line if you want HTTPS
    //SSLEngine engine = SecureChatSslContextFactory.getServerContext().createSSLEngine();
    //engine.setUseClientMode(false);
    //p.addLast("ssl", new SslHandler(engine));

//        p.addLast("idle", new IdleStateHandler(3, 0, 3, TimeUnit.SECONDS) {
//            @Override
//            protected void channelIdle(ChannelHandlerContext ctx, IdleStateEvent evt) throws Exception
//            {
//                System.out.println("--------" + evt.state());
//                //super.channelIdle(ctx, evt);
//            }
//        });

        /*
        p.addLast(new ChannelInboundByteHandlerAdapter()
        {
            private final Charset US_ASCII = Charset.forName("US-ASCII");

            @Override
            public void inboundBufferUpdated(ChannelHandlerContext ctx, ByteBuf in) throws Exception
            {
                if (in.readableBytes() < 8) return;

                // read method
                in.markReaderIndex();
                byte[] buffer = new byte[8];
                in.readBytes(buffer, 0, buffer.length);
                String method = new String(buffer, US_ASCII);
                in.resetWriterIndex();

                System.out.println(this + " / " + i.incrementAndGet() + " / '" + method + "'");
//                if (method.startsWith("CONNECT")) {
//
//                } else {
//
//                }
                ctx.fireInboundBufferUpdated();
            }
        });
        */


}
