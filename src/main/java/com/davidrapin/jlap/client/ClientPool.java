package com.davidrapin.jlap.client;

import com.davidrapin.jlap.ssl.SSLCertificate;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.handler.codec.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Date: 22/05/13 at 00:48
 *
 * @author david
 */
public class ClientPool
{
    private static final Logger log = LoggerFactory.getLogger(ClientPool.class);
    private final EventLoopGroup eventLoop;

    public ClientPool()
    {
        this(null);
    }

    public ClientPool(EventLoopGroup eventLoop)
    {
        this.eventLoop = eventLoop == null ? new NioEventLoopGroup() : eventLoop;
    }

    // connected clients by clientKey
    private final ConcurrentMap<NetLoc, HttpClient> connectedClients = new ConcurrentHashMap<NetLoc, HttpClient>();

    public void sendRequest(HttpRequest r, HttpResponseListener listener)
    {
        sendRequest(null, r, listener);
    }

    public void sendRequest(NetLoc netLoc, HttpRequest r, HttpResponseListener listener)
    {
        if (netLoc == null) netLoc = NetLoc.forRequest(r);
        HttpClient client = getClient(netLoc, null);

        // make URI relative
        String uri = r.getUri();
        if (uri.startsWith("http://") || uri.startsWith("https://"))
        {
            int pathStart = uri.indexOf('/', 8);
            if (pathStart > 0) uri = uri.substring(pathStart);
        }
        r.setUri(uri);

//        logClientStates();
        client.request(r, listener);
    }

//    private void logClientStates()
//    {
//        String s = "";
//        for (HttpClient c : connectedClients.values())
//        {
//            s += c.getHost() + "=" + c.countResponseListeners() + " | ";
//        }
//        log.debug("listeners : [" + s.substring(0, s.length()-1) + "]");
//    }

    private synchronized HttpClient getClient(final NetLoc netLoc, final ConnectListener connectListener)
    {
        HttpClient client = connectedClients.get(netLoc);
        if (client == null)
        {
            client = new HttpClient(new HttpClientListener()
            {
                @Override
                public void onServerCertificate(X509Certificate[] chain, String authType)
                {
                    SSLCertificate certificate = new SSLCertificate(chain, authType);
//                    certificates.put(netLoc, certificate);
                    if (connectListener != null) connectListener.onSuccess(certificate);
                }

                @Override
                public void onConnected(HttpClient c) { }

                @Override
                public void onConnectionFailed(HttpClient c)
                {
                    removeClient(c);
                    if (connectListener != null) connectListener.onFailure();
                }

                @Override
                public void onConnectionClosed(HttpClient c)
                {
                    removeClient(c);
                }
            }, eventLoop, netLoc);
            connectedClients.put(netLoc, client);
        }
        return client;
    }

    private HttpClient removeClient(HttpClient c)
    {
        connectedClients.remove(c.getNetLoc());
        int listeners = c.countResponseListeners();
        if (listeners > 0)
        {
            log.info("REMOVING CLIENT > " + c.getNetLoc() + " (listeners: " + listeners + ")");
        }
        return c;
    }

//    public SSLCertificate getCertificate(NetLoc netLoc)
//    {
//        return certificates.get(netLoc);
//    }

    public void connect(NetLoc targetServer, ConnectListener listener)
    {
        getClient(targetServer, listener);
    }

    public void shutdownAll()
    {
        for (HttpClient c : connectedClients.values())
        {
            c.shutdown();
        }
        connectedClients.clear();
    }

    public void shutdown(NetLoc targetServer)
    {
        HttpClient c = connectedClients.get(targetServer);
        if (c != null)
        {
            log.info("shutting down client for '{}'", targetServer);
            connectedClients.remove(targetServer);
            c.shutdown();
        }
    }
}
