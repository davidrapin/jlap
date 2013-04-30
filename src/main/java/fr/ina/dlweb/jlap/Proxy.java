package fr.ina.dlweb.jlap;

import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;

/**
 * Date: 12/03/13
 * Time: 16:12
 *
 * @author drapin
 */
public class Proxy
{
    private final int port;
    private final ChannelGroup channelGroup = new DefaultChannelGroup("JLAP");

    public Proxy(int port)
    {
        this.port = port;
    }

    public void start() {

        HttpServerPipelineInitializer factory =
                    new HttpServerPipelineInitializer(authenticationManager,
                        this.allChannels,
                        this.chainProxyManager,
                        this.ksm,
                        new DefaultRelayPipelineFactoryFactory(
                            chainProxyManager,
                            this.responseFilters, this.requestFilter,
                            this.allChannels, timer), timer, this.clientChannelFactory);
                serverBootstrap.setPipelineFactory(factory);
    }
}
