package com.davidrapin.jlap.ssl;

import org.bouncycastle.jce.X509Principal;
import sun.security.x509.X500Name;

import java.io.IOException;

/**
 * Date: 31/05/13 at 01:32
 *
 * @author david
 */
public class X50XUtils
{
    public static X509Principal createX509Principal(
        String commonName, String organizationUnit, String organization,
        String city, String countryCode, String postalCode
    ) throws IOException
    {
        return new X509Principal(
            createX500Name(commonName, organizationUnit, organization, city, countryCode, postalCode).toString()
        );
    }

    public static X500Name createX500Name(
        String commonName, String organizationUnit, String organization,
        String city, String countryCode, String postalCode
    ) throws IOException
    {
        return new X500Name(commonName, organizationUnit, organization, city, countryCode, postalCode);
    }

    public static X500Name createX500Name(String commonName, String organizationUnit, String organization, String postalCode) throws IOException
    {
        return new X500Name(commonName, organizationUnit, organization, postalCode);
    }

    public static X500Name createX500Name(String commonName) throws IOException
    {
        return new X500Name("CN=" + commonName);
    }

    public static X500Name parseX500Name(String name) throws IOException
    {
        return new X500Name(name);
    }
}
