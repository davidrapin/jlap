package com.davidrapin.jlap;

import com.davidrapin.jlap.proxy.HttpProxy;
import org.testng.annotations.Test;

/**
 * Date: 12/03/13
 * Time: 16:12
 *
 * @author drapin
 */
@Test
public class ProxyTest
{
    public void test() throws Exception
    {
        HttpProxy httpProxy = new HttpProxy(8080);
        httpProxy.run();
    }

}
