package com.davidrapin.jlap.client;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Date: 07/03/13
 * Time: 14:40
 *
 * @author drapin
 */
public class HttpClient implements HttpResponseListener
{
    private static AtomicInteger c = new AtomicInteger(0);

    private final int id;
    private final String host;
    private final int port;
    private final boolean ssl;

    private ChannelFuture futureConnectedChannel;

    private final HttpClientListener clientListener;
    private final Queue<HttpResponseListener> responseListeners = new ConcurrentLinkedQueue<HttpResponseListener>();

    public String getServerKey()
    {
        return getServerKey(host, port, ssl);
    }

    public static String getServerKey(String host, int port, boolean ssl)
    {
        return host + ":" + port + (ssl ? ":ssl" : "");
    }

    public HttpClient(HttpClientListener clientListener, EventLoopGroup eventLoop, HttpRequest r)
    {
        this(clientListener, eventLoop, getURL(r));
    }

    public static URL getURL(HttpRequest r)
    {
        try
        {
            if (r.getUri().startsWith("h"))
            {
                return new URI(r.getUri()).toURL();
            }
            else
            {
                return new URI("http://" + r.headers().get("Host") + r.getUri()).toURL();
            }
        }
        catch (MalformedURLException e)
        {
            throw new RuntimeException(e);
        }
        catch (URISyntaxException e)
        {
            throw new RuntimeException(e);
        }
    }

    public HttpClient(HttpClientListener clientListener, EventLoopGroup eventLoop, URL u)
    {
        this(
            clientListener,
            eventLoop,
            u.getHost(),
            u.getPort() < 0 ? u.getDefaultPort() : u.getPort(),
            u.getProtocol().equals("https")
        );
    }

    public HttpClient(HttpClientListener clientListener, EventLoopGroup eventLoop, String host)
    {
        this(clientListener, eventLoop, host, 80);
    }

    public HttpClient(HttpClientListener clientListener, EventLoopGroup eventLoop, String host, int port)
    {
        this(clientListener, eventLoop, host, port, false);
    }

    public HttpClient(HttpClientListener clientListener, EventLoopGroup eventLoop, String host, int port, boolean ssl)
    {
        this.clientListener = clientListener;
        this.host = host;
        this.port = port;
        this.ssl = ssl;
        id = c.incrementAndGet();

        logState("started");

        connect(eventLoop);
    }

    protected void logState(String state)
    {
        System.out.println(System.currentTimeMillis() + " [CLIENT-" + id + " " + host + ":" + port + (ssl ? " SSL" : "") + "] :" + state);
    }

    private void connect(EventLoopGroup eventLoop)
    {
        // Configure the client.
        final Bootstrap bootstrap = new Bootstrap();
        try
        {
            bootstrap.group(eventLoop)
                .channel(NioSocketChannel.class)
                .handler(new HttpClientChannelInitializer(ssl, clientListener, this));

            // Make the connection attempt.
            futureConnectedChannel = bootstrap.connect(host, port);
            futureConnectedChannel.addListener(new ChannelFutureListener()
            {
                @Override
                public void operationComplete(ChannelFuture future) throws Exception
                {
                    if (future.isSuccess())
                    {
                        // connected :)
                        futureConnectedChannel = future.channel().newSucceededFuture();

                        logState("connected");
                        clientListener.onConnected(HttpClient.this);

                        // listener to connection end
                        futureConnectedChannel.channel().closeFuture().addListener(new ChannelFutureListener()
                        {
                            @Override
                            public void operationComplete(ChannelFuture future) throws Exception
                            {
                                logState("disconnected");
                                clientListener.onConnectionClosed(HttpClient.this);

                                // Shut down executor threads to exit.
                                //bootstrap.shutdown();
                            }
                        });
                    }
                    else
                    {
                        logState("connection-failed");
                        clientListener.onConnectionFailed(HttpClient.this);
                    }
                }
            });
        }
        catch (Exception e)
        {
            // Shut down executor threads to exit.
            logState("connection-error");
            throw new RuntimeException(e);
        }
    }

    public synchronized void request(final HttpRequest request, final HttpResponseListener listener)
    {
        // when connected
        futureConnectedChannel.addListener(new ChannelFutureListener()
        {
            @Override
            public void operationComplete(ChannelFuture future) throws Exception
            {

                // Send the HTTP request.
                futureConnectedChannel.channel().write(request).addListener(new ChannelFutureListener()
                {
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception
                    {
                        if (future.isSuccess())
                        {
                            responseListeners.add(listener);
                            logState("send > " + request.getMethod() + " " + request.getUri());
                        }
                        else
                        {
                            future.channel().close();
                            onError(
                                "could not send request > " + request.getMethod() + " " + request.getUri(),
                                future.cause()
                            );
                        }
                    }
                });
            }
        });
    }

    public void waitForClose()
    {
        futureConnectedChannel.channel().closeFuture().syncUninterruptibly();
    }

//    public void disconnect()
//    {
//        clientChannelFuture.channel().disconnect();
//    }

    @Override
    public final void onHttpResponse(HttpResponse response, ChannelHandlerContext ctx)
    {
        responseListeners.peek().onHttpResponse(response, ctx);
    }

    @Override
    public final void onHttpContent(HttpContent content, ChannelHandlerContext ctx)
    {
        responseListeners.peek().onHttpContent(content, ctx);
    }

    @Override
    public void onHttpContentEnd(ChannelHandlerContext ctx)
    {
        responseListeners.remove().onHttpContentEnd(ctx);
    }

    @Override
    public void onError(String message, Throwable cause)
    {
        HttpResponseListener listener = responseListeners.poll();
        if (listener == null)
        {
            logState(message + " (no pending request) (" + cause + ")");
        }
        else
        {
            listener.onError(message, cause);
        }
    }

    public int countResponseListeners()
    {
        return responseListeners.size();
    }
}
