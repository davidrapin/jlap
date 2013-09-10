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
            // copy the request of the client to make our own
            final FullHttpRequest requestCopy = new DefaultFullHttpRequest(
                request.getProtocolVersion(),
                request.getMethod(),
                request.getUri(),
                request.data().readableBytes() == 0 ? Unpooled.buffer(0) : request.data().copy()
            );
            requestCopy.trailingHeaders().add(request.trailingHeaders());
            requestCopy.headers().add(request.headers());

            // ongoing https connect, store requests somewhere for replay (todo: test this)
            if (awaitingConnect) {
                requestsDuringConnect.add(requestCopy);
                return;
            }

            // https initialization
            if (request.getMethod().equals(HttpMethod.CONNECT))
            {
                targetServer = NetLoc.forRequest(request);
                awaitingConnect = true;
                if (requestsDuringConnect.size() > 0) {
                    System.out.println("> non empty request buffer (requests-during-connect)");
                }
                requestsDuringConnect.clear();

                // oen connection to remote:server
                clientPool.connect(targetServer, new ConnectListener()
                {
                    @Override
                    public void onSuccess(final SSLCertificate serverCertificate)
                    {
                        System.out.println("SSL Connect client-side handshake OK");

                        // remote:server success, response 200:ok to remote:client
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
                                    // 200:ok to remote:client sent successfully
                                    System.out.println("SSL Connect proxy-side : notified");

                                    // add SSL engine between us and remote:client
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

                                    // start handshake with remote:client
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
                // classic http request
                clientPool.sendRequest(targetServer, requestCopy, new ResponseForwarder(requestContext, requestCopy));
            }
        }
    }

    private static void send100Continue(ChannelHandlerContext ctx)
    {
        HttpResponse response = new DefaultFullHttpResponse(HTTP_1_1, CONTINUE);
        ctx.write(response);
    }

                    /*
                sendHttpResponse(
                    requestContext,
                    request,
                    new DefaultFullHttpResponse(request.getProtocolVersion(), BAD_GATEWAY)
                );
                */

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception
    {
        System.out.println("proxy error !");
        cause.printStackTrace();

        //super.exceptionCaught(ctx, cause);
    }
}
