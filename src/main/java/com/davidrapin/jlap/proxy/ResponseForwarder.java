package com.davidrapin.jlap.proxy;

import com.davidrapin.jlap.client.HttpResponseListener;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicInteger;

import static io.netty.handler.codec.http.HttpHeaders.*;

/**
 * Date: 24/05/13 at 22:40
 *
 * @author david
 */
class ResponseForwarder implements HttpResponseListener
{
    private static final Logger log = LoggerFactory.getLogger(ResponseForwarder.class);

    private final ChannelHandlerContext requestContext;
    private final FullHttpRequest request;

    private final boolean requestIsKeepAlive;
    private boolean responseIsKeepAlive = false;
    private Long responseContentLength = null;
    private boolean clientConnectionClosed = false;

    private final AtomicInteger sizeToWrite = new AtomicInteger(0);
    private final AtomicInteger sizeWritten = new AtomicInteger(0);

    public ResponseForwarder(ChannelHandlerContext requestContext, FullHttpRequest request)
    {
        this.requestContext = requestContext;
        this.request = request;
        requestIsKeepAlive = isKeepAlive(request);

        requestContext.channel().closeFuture().addListener(new ChannelFutureListener()
        {
            @Override
            public void operationComplete(ChannelFuture future) throws Exception
            {
                clientConnectionClosed = true;
                log.info("[CLIENT CLOSED CONNECTION] " + ResponseForwarder.this.request.getUri());
            }
        });
    }

    @Override
    public void onHttpResponse(HttpResponse response, ChannelHandlerContext responseContext)
    {
        responseIsKeepAlive = isKeepAlive(response);

        responseContentLength = getContentLength(response, -1);
        if (responseContentLength < 0) responseContentLength = null;

        log.debug(request.getUri() + " : response headers (" + response.getStatus() + ")");

        if (clientConnectionClosed) return;

        requestContext.channel().write(response).addListener(new ChannelFutureListener()
        {
            @Override
            public void operationComplete(ChannelFuture future) throws Exception
            {
                //log.debug(request.getUri() + " > response headers WRITTEN");
            }
        });
    }

    @Override
    public void onHttpContent(HttpContent content, final ChannelHandlerContext responseContext)
    {
        if (clientConnectionClosed) return;

        HttpContent c = content.copy();

        final int size = c.data().readableBytes();
        sizeToWrite.addAndGet(size);

        requestContext.channel().write(c).addListener(new ChannelFutureListener()
        {
            @Override
            public void operationComplete(ChannelFuture future) throws Exception
            {
                if (!future.isSuccess())
                {
                    responseContext.channel().close();
                    requestContext.channel().close();

                    Throwable t = future.cause();
                    //if (t != null) t.printStackTrace();
                    log.error("could not forward response for " + request.getUri(), t);
                    return;
                }

                sizeWritten.addAndGet(size);
            }
        });
    }

    @Override
    public void onHttpContentEnd(ChannelHandlerContext ctx)
    {
        log.debug(
            request.getUri() + " > response end (content-length:" + responseContentLength +
            ", written:" + sizeWritten.get() +
            ", left: " + (sizeToWrite.get() - sizeWritten.get()) + ")"
        );

        if (!requestIsKeepAlive || !responseIsKeepAlive || responseContentLength == null)
        {
            requestContext.flush().addListener(ChannelFutureListener.CLOSE);
        }
    }

    @Override
    public void onError(String message, Throwable cause)
    {
        if (clientConnectionClosed) return;

        log.error("[ERROR] (" + message + ") > " + request.getUri());
        //if (cause != null) cause.printStackTrace();

        sendStatusAndClose(
            requestContext.channel(),
            request.getProtocolVersion(),
            HttpResponseStatus.BAD_GATEWAY
        );
    }

    public static void sendStatusAndClose(Channel channel, HttpVersion version, HttpResponseStatus status)
    {
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(version, status);
        setContentLength(response, 0);
        setKeepAlive(response, false);
        channel.write(response).addListener(flushAndClose());
    }

    public static ChannelFutureListener flushAndClose()
    {
        return new ChannelFutureListener()
        {
            @Override
            public void operationComplete(ChannelFuture future) throws Exception
            {
                future.channel().flush().addListener(ChannelFutureListener.CLOSE);
            }
        };
    }

}
