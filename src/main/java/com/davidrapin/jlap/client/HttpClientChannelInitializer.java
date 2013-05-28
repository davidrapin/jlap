package com.davidrapin.jlap.client;

import com.davidrapin.jlap.ssl.SSLContextFactory;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundMessageHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.lang.ref.WeakReference;

/**
 * Date: 19/05/13 at 17:45
 *
 * @author david
 */
public class HttpClientChannelInitializer extends ChannelInitializer<SocketChannel>
{
    private final boolean ssl;
    private final HttpResponseListener responseListener;
    private final WeakReference<HttpClientListener> clientListener;

    public HttpClientChannelInitializer(boolean ssl, HttpClientListener clientListener, HttpResponseListener responseListener)
    {
        this.ssl = ssl;
        this.responseListener = responseListener;
        this.clientListener = new WeakReference<HttpClientListener>(clientListener);
    }

    @Override
    public void initChannel(SocketChannel ch) throws Exception
    {
        // Create a default pipeline implementation.
        ChannelPipeline p = ch.pipeline();

        //p.addLast("log", new LoggingHandler(LogLevel.INFO));

        // Enable HTTPS
        if (ssl)
        {
            SSLContext clientContext = SSLContextFactory.getClientContext(clientListener.get());
            SSLEngine engine = clientContext.createSSLEngine();
            engine.setUseClientMode(true);

            p.addLast("ssl", new SslHandler(engine));
        }

        // bytes to http content
        p.addLast("codec", new HttpClientCodec());

        // automatic content decompression.
        //p.addLast("inflater", new HttpContentDecompressor());

        p.addLast(new ChannelInboundMessageHandlerAdapter<HttpObject>()
        {
            @Override
            public void messageReceived(ChannelHandlerContext ctx, HttpObject msg) throws Exception
            {
                if (msg instanceof HttpResponse)
                {
                    HttpResponse r = (HttpResponse) msg;
                    responseListener.onHttpResponse(r, ctx);
                }
                else if (msg instanceof HttpContent)
                {
                    HttpContent c = (HttpContent) msg;

                    responseListener.onHttpContent(c, ctx);

                    if (c instanceof LastHttpContent) {
                        responseListener.onHttpContentEnd(ctx);
                    }
                }
            }

            @Override
            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception
            {
                if (cause instanceof IOException)
                {
                    responseListener.onError("remote server error", cause);
                }
                else
                {
                    responseListener.onError("unexpected error", cause);
                    cause.printStackTrace();
                }

                // terminate client
                if (ctx.channel().isOpen())
                {
                    ctx.channel().close();
                }
                else
                {
                    ctx.close();
                }
            }
        });
    }


}
