package com.davidrapin.jlap.client;

import com.davidrapin.jlap.ssl.SSLCertificate;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.handler.codec.http.HttpRequest;

import java.net.URL;
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
    private final ConcurrentMap<String, SSLCertificate> certificates = new ConcurrentHashMap<String, SSLCertificate>();

    public ClientPool()
    {
        this(null);
    }

    public ClientPool(EventLoopGroup eventLoop)
    {
        this.eventLoop = eventLoop == null ? new NioEventLoopGroup() : eventLoop;
    }

    // connected clients by clientKey
    private final ConcurrentMap<String, HttpClient> connectedClients = new ConcurrentHashMap<String, HttpClient>();

    public void sendRequest(HttpRequest r, HttpResponseListener listener)
    {
        sendRequest(null, r, listener);
    }

    public void sendRequest(String serverKey, HttpRequest r, HttpResponseListener listener)
    {
        if (serverKey == null) serverKey = getServerKey(r);
        HttpClient client = getClient(r, serverKey);

        // make URI relative
        String uri = r.getUri();
        if (uri.startsWith("http"))
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
//            s += c.getServerKey() + "=" + c.countResponseListeners() + " | ";
//        }
//        System.out.println("listeners : [" + s.substring(0, s.length()-1) + "]");
//    }

    private synchronized HttpClient getClient(HttpRequest r, final String serverKey)
    {
        HttpClient client = connectedClients.get(serverKey);
        if (client == null)
        {
            client = new HttpClient(new HttpClientListener()
            {
                @Override
                public void onServerCertificate(X509Certificate[] chain, String authType)
                {
                    certificates.put(serverKey, new SSLCertificate(chain, authType));
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
            }, eventLoop, r);
            connectedClients.put(client.getServerKey(), client);
        }
        return client;
    }

    private HttpClient removeClient(HttpClient c)
    {
        connectedClients.remove(c.getServerKey());
        int listeners = c.countResponseListeners();
        if (listeners > 0)
        {
            System.out.println("REMOVING CLIENT > " + c.getServerKey() + " (listeners: " + listeners + ")");
        }
        return c;
    }

    public SSLCertificate getCertificate(HttpRequest r)
    {
        String serverKey = getServerKey(r);
        return certificates.get(serverKey);
    }

    public static String getServerKey(HttpRequest r)
    {
        URL url = HttpClient.getURL(r);
        return HttpClient.getServerKey(
            url.getHost(),
            url.getPort() < 0 ? url.getDefaultPort() : url.getPort(),
            url.getProtocol().equals("https")
        );
    }
}
