package com.davidrapin.jlap.client;

import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;

import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * Date: 28/05/13 at 22:50
 *
 * @author david
 */
public class NetLoc implements Serializable
{
    public final String host;
    public final int port;
    public final boolean ssl;

    public NetLoc(String host, int port, boolean ssl)
    {
        this.host = host;
        this.port = port;
        this.ssl = ssl;
    }

    @SuppressWarnings("RedundantIfStatement")
    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        NetLoc netLoc = (NetLoc) o;

        if (port != netLoc.port) return false;
        if (ssl != netLoc.ssl) return false;
        if (!host.equals(netLoc.host)) return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = host.hashCode();
        result = 31 * result + port;
        result = 31 * result + (ssl ? 1 : 0);
        return result;
    }

    @Override
    public String toString()
    {
        return host + ":" + port + (ssl ? ":ssl" : "");
    }

    public static NetLoc forRequest(HttpRequest r)
    {
        URL u = getURL(r);
        return new NetLoc(
            u.getHost(),
            u.getPort() < 0 ? u.getDefaultPort() : u.getPort(),
            u.getProtocol().equals("https") || r.getMethod().equals(HttpMethod.CONNECT)
        );
    }

    public static URL getURL(HttpRequest r)
    {
        try
        {
            String uri = r.getUri();
            if (r.getMethod().equals(HttpMethod.CONNECT)) {
                return new URL("https://" + uri + "/");
            } else {
                if (uri.startsWith("http://") || uri.startsWith("https://"))
                {
                    return new URI(uri).toURL();
                }
                else
                {
                    return new URI("http://" + r.headers().get("Host") + uri).toURL();
                }
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
}
