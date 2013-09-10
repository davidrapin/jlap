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
    private final NetLoc netLoc;

    private ChannelFuture futureConnectedChannel;

    private final HttpClientListener clientListener;
    private final Queue<HttpResponseListener> responseListeners = new ConcurrentLinkedQueue<HttpResponseListener>();

    public NetLoc getNetLoc()
    {
        return netLoc;
    }

    public HttpClient(HttpClientListener clientListener, EventLoopGroup eventLoop, String host)
    {
        this(clientListener, eventLoop, host, 80);
    }

    public HttpClient(HttpClientListener clientListener, EventLoopGroup eventLoop, String host, int port)
    {
        this(clientListener, eventLoop, new NetLoc(host, port, false));
    }

    public HttpClient(HttpClientListener clientListener, EventLoopGroup eventLoop, NetLoc netLoc)
    {
        this.clientListener = clientListener;
        this.netLoc = netLoc;
        id = c.incrementAndGet();

        logState("started");

        connect(eventLoop);
    }

    protected void logState(String state)
    {
        System.out.println(System.currentTimeMillis() + " [CLIENT-" + id + " " + netLoc + "] :" + state);
    }

    private void connect(EventLoopGroup eventLoop)
    {
        // Configure the client.
        final Bootstrap bootstrap = new Bootstrap();
        try
        {
            bootstrap.group(eventLoop)
                .channel(NioSocketChannel.class)
                .handler(new HttpClientChannelInitializer(netLoc.ssl, clientListener, this));

            // Make the connection attempt.
            futureConnectedChannel = bootstrap.connect(netLoc.host, netLoc.port);
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
        HttpResponseListener hrl = responseListeners.peek();
        if (hrl == null) {
            System.out.println("> response with no request (" + response + ")");
            return;
        }
        hrl.onHttpResponse(response, ctx);
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

    public void shutdown()
    {
        futureConnectedChannel.channel().disconnect();
    }
}
