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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private static final Logger log = LoggerFactory.getLogger(HttpProxyHandler.class);

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
                    log.warn("clearing non empty request buffer (requests-during-connect)");
                }
                requestsDuringConnect.clear();

                // oen connection to remote:server
                clientPool.connect(targetServer, new ConnectListener()
                {
                    @Override
                    public void onSuccess(final SSLCertificate serverCertificate)
                    {
                        log.debug("[{}] SSL-Connect proxy:server [handshake OK]", targetServer);

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
                                    log.debug("[{}] SSL-Connect client:proxy [client notified]", targetServer);

                                    // add SSL engine between us and remote:client
                                    SSLEngine engine = sslContextFactory.getServerContext(targetServer, serverCertificate).createSSLEngine();
                                    engine.setUseClientMode(false);
                                    final SslHandler sslhandler = new SslHandler(engine)
                                    {
                                        @Override
                                        public void channelInactive(ChannelHandlerContext ctx) throws Exception
                                        {
                                            super.channelInactive(ctx);
                                            clientPool.shutdown(targetServer);
                                        }

                                        @Override
                                        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception
                                        {
                                            log.error("[" + targetServer + "] SSL error", cause);
                                            //super.exceptionCaught(ctx, cause);
                                            clientPool.shutdown(targetServer);
                                        }
                                    };
                                    future.channel().pipeline().addFirst("ssl-server", sslhandler);

                                    // start handshake with remote:client
                                    log.debug("[{}] SSL-connect client:proxy [starting handshake]", targetServer);
                                    sslhandler.handshake(future.channel().newPromise()).addListener(new ChannelFutureListener()
                                    {
                                        @Override
                                        public void operationComplete(ChannelFuture future) throws Exception
                                        {
                                            log.debug("[{}] SSL-connect client:proxy [handshake success : {}]",
                                                    targetServer,
                                                    future.isSuccess()
                                            );
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
                        log.warn("[{}] SSL-Connect proxy:server [handshake FAILED]", targetServer);
                        requestContext.channel()
                            .write(new DefaultFullHttpResponse(requestCopy.getProtocolVersion(), BAD_GATEWAY))
                            .addListener(ChannelFutureListener.CLOSE);
                    }
                });
            }
            else
            {
                if (targetServer != null) {
                    String host = requestCopy.headers().get("Host");
                    System.out.println(">> TARGET=" + targetServer + " __ HOST=" + host);
                }

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
        log.error("PROXY ERROR", cause);
        //cause.printStackTrace();
        //super.exceptionCaught(ctx, cause);
    }
}
