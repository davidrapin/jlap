package fr.ina.dlweb.jlap;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.timeout.IdleStateHandler;

/**
 * Date: 12/03/13
 * Time: 16:16
 *
 * @author drapin
 */
public class HttpServerPipelineInitializer extends ChannelInitializer<SocketChannel>
{
    @Override
    protected void initChannel(SocketChannel channel) throws Exception
    {
        ChannelPipeline pipeline = channel.pipeline();

        // We want to allow longer request lines, headers, and chunks respectively.
        pipeline.addLast("decoder", new HttpRequestDecoder(8192, 8192*2, 8192*2));
        pipeline.addLast("encoder", new ProxyHttpResponseEncoder());

        pipeline.addLast("idle", new IdleStateHandler(0, 0, 70));
        pipeline.addLast("idleAware", new IdleRequestHandler(httpRequestHandler));

        HttpRequestHandler httpRequestHandler =
                    new HttpRequestHandler(this.cacheManager, authenticationManager,
                    this.channelGroup, this.chainProxyManager,
                    relayPipelineFactoryFactory, this.clientChannelFactory);
        pipeline.addLast("handler", httpRequestHandler);
    }
}
