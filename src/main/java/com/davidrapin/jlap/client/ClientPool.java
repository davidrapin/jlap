package com.davidrapin.jlap.client;

import com.davidrapin.jlap.ssl.SSLCertificate;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.handler.codec.http.HttpRequest;

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
    private final EventLoopGroup eventLoop;
    private final ConcurrentMap<NetLoc, SSLCertificate> certificates = new ConcurrentHashMap<NetLoc, SSLCertificate>();

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
        HttpClient client = getClient(netLoc);

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
//        System.out.println("listeners : [" + s.substring(0, s.length()-1) + "]");
//    }

    private synchronized HttpClient getClient(final NetLoc netLoc)
    {
        HttpClient client = connectedClients.get(netLoc);
        if (client == null)
        {
            client = new HttpClient(new HttpClientListener()
            {
                @Override
                public void onServerCertificate(X509Certificate[] chain, String authType)
                {
                    certificates.put(netLoc, new SSLCertificate(chain, authType));
                }

                @Override
                public void onConnected(HttpClient c) { }

                @Override
                public void onConnectionFailed(HttpClient c)
                {
                    removeClient(c);
                }

                @Override
                public void onConnectionClosed(HttpClient c)
                {
                    removeClient(c);
                }
            }, eventLoop, netLoc);
            connectedClients.put(client.getNetLoc(), client);
        }
        return client;
    }

    private HttpClient removeClient(HttpClient c)
    {
        connectedClients.remove(c.getNetLoc());
        int listeners = c.countResponseListeners();
        if (listeners > 0)
        {
            System.out.println("REMOVING CLIENT > " + c.getNetLoc() + " (listeners: " + listeners + ")");
        }
        return c;
    }

    public SSLCertificate getCertificate(NetLoc netLoc)
    {
        return certificates.get(netLoc);
    }

}
