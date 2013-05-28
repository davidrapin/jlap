package com.davidrapin.jlap;

import com.davidrapin.jlap.client.HttpResponseListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpResponse;

import java.nio.charset.Charset;
import java.util.Map;

/**
 * Date: 22/05/13 at 02:41
 *
 * @author david
 */
public class ResponseListener implements HttpResponseListener
{
    private final String prefix;

    public static String header2string(HttpHeaders h)
    {
        String r = "";
        for (Map.Entry<String, String> e : h)
        {
            r += e.getKey() + "=" + e.getValue() + "\n";
        }
        return r;
    }

    public ResponseListener(String prefix)
    {
        this.prefix = prefix;
    }

    @Override
    public void onHttpResponse(HttpResponse r, ChannelHandlerContext ctx)
    {
        System.out.println(prefix + "__ response headers : (" + r.getProtocolVersion() + ") " + r.getStatus());
        System.out.println(header2string(r.headers()) + "\n");
    }

    @Override
    public void onHttpContent(HttpContent content, ChannelHandlerContext ctx)
    {
        String data = content.data().toString(Charset.forName("UTF-8"));
        System.out.println(prefix + "__ response data : \n'" + data + "'");
    }

    @Override
    public void onHttpContentEnd(ChannelHandlerContext ctx)
    {
        System.out.println(prefix + "__ response end : -----------------------------\n");
    }

    @Override
    public void onError(String message, Throwable cause)
    {
        System.out.println(prefix + "__ ERROR : " + message + " > " + cause);
    }
}
