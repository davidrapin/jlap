package com.davidrapin.jlap.ssl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/**
 * Date: 05/06/13 at 23:20
 *
 * @author david
 */
public class KeyGenerator
{
    private static KeyPair generateKeyPair(int keySize, KeyPairGenerator keyPairGenerator)
    {
        keyPairGenerator.initialize(keySize, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generaKeyPair(int keySize, String algorithm)
    {
        try
        {
            return generateKeyPair(keySize, KeyPairGenerator.getInstance(algorithm));
        }
        catch (java.security.NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
    }
}
