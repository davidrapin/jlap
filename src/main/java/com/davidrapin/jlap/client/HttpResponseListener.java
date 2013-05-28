package com.davidrapin.jlap.client;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpResponse;

import java.security.cert.X509Certificate;

/**
 * Date: 20/05/13 at 21:43
 *
 * @author david
 */
public interface HttpResponseListener
{
    void onHttpResponse(HttpResponse response, ChannelHandlerContext ctx);

    void onHttpContent(HttpContent content, ChannelHandlerContext ctx);

    void onHttpContentEnd(ChannelHandlerContext ctx);

    void onError(String message, Throwable cause);
}
