package com.davidrapin.jlap;

import com.davidrapin.jlap.proxy.HttpProxy;
import org.testng.annotations.Test;

/**
 * Date: 12/03/13
 * Time: 16:12
 *
 * @author drapin
 */
public class ProxyTest
{
    public static void main(String[] args) throws Exception {
        HttpProxy httpProxy = new HttpProxy(8080);
        httpProxy.run();
    }

}
