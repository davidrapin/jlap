package com.davidrapin.jlap.proxy;

import com.davidrapin.jlap.client.ClientPool;
import com.davidrapin.jlap.ssl.SSLContextFactory;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundMessageHandlerAdapter;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.CharsetUtil;

import javax.net.ssl.SSLEngine;

import static io.netty.handler.codec.http.HttpHeaders.*;
import static io.netty.handler.codec.http.HttpResponseStatus.CONTINUE;
import static io.netty.handler.codec.http.HttpResponseStatus.OK;
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
    private String sslServerKey = null;

    public HttpProxyHandler(ClientPool clientPool)
    {
        this.clientPool = clientPool;
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


            if (request.getMethod().equals(HttpMethod.CONNECT))
            {
                /*
                sendHttpResponse(
                    requestContext,
                    request,
                    new DefaultFullHttpResponse(request.getProtocolVersion(), BAD_GATEWAY)
                );
                */
                sslServerKey = request.getUri() + ":ssl";
                requestContext.channel().write(new DefaultFullHttpResponse(request.getProtocolVersion(), OK)).addListener(
                    new ChannelFutureListener()
                    {
                        @Override
                        public void operationComplete(ChannelFuture future) throws Exception
                        {
                            System.out.println("!! :)");

                            SSLEngine engine = SSLContextFactory.getServerContext().createSSLEngine();
                            engine.setUseClientMode(false);
                            final SslHandler sslhandler = new SslHandler(engine) {
                                @Override
                                public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception
                                {
                                    System.out.println("> error : " + cause);
                                    //super.exceptionCaught(ctx, cause);
                                }
                            };
                            future.channel().pipeline().addFirst("ssl-server", sslhandler);

                            sslhandler.handshake(future.channel().newPromise());
                        }
                    }
                );
                /*

                */
            }
            else
            {
                clientPool.sendRequest(sslServerKey, requestCopy, new ResponseForwarder(requestContext, requestCopy));
            }
        }
    }

    private static void sendHttpResponse(
        ChannelHandlerContext requestContext, FullHttpRequest request, FullHttpResponse response
    )
    {
        boolean responseIsError = response.getStatus().code() >= 400;

        // Generate an error page if response getStatus code is not OK (200).
        if (responseIsError)
        {
            response.data().writeBytes(Unpooled.copiedBuffer(response.getStatus().toString(), CharsetUtil.UTF_8));
            setContentLength(response, response.data().readableBytes());
        }

        // Send the response and close the connection if necessary.
        ChannelFuture f = requestContext.channel().write(response);
        if (!isKeepAlive(request) || responseIsError)
        {
            f.addListener(ChannelFutureListener.CLOSE);
        }
    }

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
