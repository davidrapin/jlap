package com.davidrapin.jlap.proxy;

import com.davidrapin.jlap.client.ClientPool;
import com.davidrapin.jlap.client.ConnectListener;
import com.davidrapin.jlap.client.NetLoc;
import com.davidrapin.jlap.ssl.SSLCertificate;
import com.davidrapin.jlap.ssl.SSLContextFactory;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundMessageHandlerAdapter;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLEngine;
import java.nio.charset.Charset;
import java.util.concurrent.ConcurrentLinkedQueue;

import static io.netty.handler.codec.http.HttpHeaders.is100ContinueExpected;
import static io.netty.handler.codec.http.HttpResponseStatus.*;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;

/**
 * Date: 03/05/13 at 00:35
 *
 * @author david
 */
public class HttpProxyHandler extends ChannelInboundMessageHandlerAdapter<FullHttpRequest>
{
    //    private static final Charset US_ASCII = Charset.forName("US-ASCII");
    private final ClientPool clientPool;
    private final SSLContextFactory sslContextFactory;
    private NetLoc targetServer = null;
    private boolean awaitingConnect = false;
    private final ConcurrentLinkedQueue<FullHttpRequest> requestsDuringConnect = new ConcurrentLinkedQueue<FullHttpRequest>();

    public HttpProxyHandler(ClientPool clientPool, SSLContextFactory sslContextFactory)
    {
        this.clientPool = clientPool;
        this.sslContextFactory = sslContextFactory;
    }

    @Override
    public void messageReceived(final ChannelHandlerContext requestContext, FullHttpRequest request) throws Exception
    {
        if (is100ContinueExpected(request))
        {
            send100Continue(requestContext);
        }
        else
        {
            final FullHttpRequest requestCopy = new DefaultFullHttpRequest(
                request.getProtocolVersion(),
                request.getMethod(),
                request.getUri(),
                request.data().readableBytes() == 0 ? Unpooled.buffer(0) : request.data().copy()
            );
            requestCopy.trailingHeaders().add(request.trailingHeaders());
            requestCopy.headers().add(request.headers());

            if (awaitingConnect) {
                requestsDuringConnect.add(requestCopy);
                return;
            }

            if (request.getMethod().equals(HttpMethod.CONNECT))
            {
                /*
                sendHttpResponse(
                    requestContext,
                    request,
                    new DefaultFullHttpResponse(request.getProtocolVersion(), BAD_GATEWAY)
                );
                */
                targetServer = NetLoc.forRequest(request);
                awaitingConnect = true;
                requestsDuringConnect.clear();

                // send proxy OK to connect
                clientPool.connect(targetServer, new ConnectListener()
                {
                    @Override
                    public void onSuccess(final SSLCertificate serverCertificate)
                    {
                        System.out.println("SSL Connect client-side handshake OK");

                        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                            requestCopy.getProtocolVersion(),
                            OK,
                            Unpooled.copiedBuffer("Connect OK", Charset.forName("US-ASCII"))
                        );
                        requestContext.channel().write(response).addListener(
                            new ChannelFutureListener()
                            {
                                @Override
                                public void operationComplete(ChannelFuture future) throws Exception
                                {
                                    // connect OK
                                    System.out.println("SSL Connect proxy-side : notified");

                                    // add SSL engine to receive communication
                                    SSLEngine engine = sslContextFactory.getServerContext(targetServer, serverCertificate).createSSLEngine();
                                    engine.setUseClientMode(false);
                                    final SslHandler sslhandler = new SslHandler(engine)
                                    {
                                        @Override
                                        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception
                                        {
                                            System.out.println("> SSL error : " + cause);
                                            //super.exceptionCaught(ctx, cause);
                                        }
                                    };
                                    future.channel().pipeline().addFirst("ssl-server", sslhandler);

                                    // start handshake
                                    System.out.println("SSL connect : starting proxy-side handshake");
                                    sslhandler.handshake(future.channel().newPromise()).addListener(new ChannelFutureListener()
                                    {
                                        @Override
                                        public void operationComplete(ChannelFuture future) throws Exception
                                        {
                                            System.out.println("SSL proxy-side handshake : success?=" + future.isSuccess());
                                            if(!future.isSuccess()) {
                                                future.channel().close();
                                            } else {
                                                while (!requestsDuringConnect.isEmpty()) {
                                                    future.channel().write(requestsDuringConnect.remove());
                                                }
                                                awaitingConnect = false;
                                            }
                                        }
                                    });
                                }
                            }
                        );
                    }

                    @Override
                    public void onFailure()
                    {
                        System.out.println("SSL Connect client-side handshake FAILED");
                        requestContext.channel()
                            .write(new DefaultFullHttpResponse(requestCopy.getProtocolVersion(), BAD_GATEWAY))
                            .addListener(ChannelFutureListener.CLOSE);
                    }
                });
            }
            else
            {
                clientPool.sendRequest(targetServer, requestCopy, new ResponseForwarder(requestContext, requestCopy));
            }
        }
    }

//    private static void sendHttpResponse(
//        ChannelHandlerContext requestContext, FullHttpRequest request, FullHttpResponse response
//    )
//    {
//        boolean responseIsError = response.getStatus().code() >= 400;
//
//        // Generate an error page if response getStatus code is not OK (200).
//        if (responseIsError)
//        {
//            response.data().writeBytes(Unpooled.copiedBuffer(response.getStatus().toString(), CharsetUtil.UTF_8));
//            setContentLength(response, response.data().readableBytes());
//        }
//
//        // Send the response and close the connection if necessary.
//        ChannelFuture f = requestContext.channel().write(response);
//        if (!isKeepAlive(request) || responseIsError)
//        {
//            f.addListener(ChannelFutureListener.CLOSE);
//        }
//    }

    private static void send100Continue(ChannelHandlerContext ctx)
    {
        HttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, CONTINUE);
        ctx.write(response);
    }

//    private static void sendBadGatewayAndClose(HttpVersion version, ChannelHandlerContext ctx)
//    {
//        HttpResponse response = new DefaultFullHttpResponse(version, BAD_GATEWAY);
//        ctx.write(response).addListener(new ChannelFutureListener()
//        {
//            @Override
//            public void operationComplete(ChannelFuture future) throws Exception
//            {
//                future.channel().flush().addListener(CLOSE);
//            }
//        });
//    }


    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception
    {
        System.out.println("proxy error !");
        cause.printStackTrace();

        //super.exceptionCaught(ctx, cause);
    }
}
