package fr.ina.dlweb.jlap;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.util.HashSet;
import java.util.Set;

/**
 * Date: 07/03/13
 * Time: 14:40
 *
 * @author drapin
 */
public class ProxyTest
{
    private final int port;

    public static void main(String[] args) throws Exception
    {
        ProxyTest p = new ProxyTest(8080);
        p.run();
    }

    public ProxyTest(int port)
    {
        this.port = port;
    }

    private final Set<Integer> sslChannels = new HashSet<Integer>();

    private final class HTTPSHandler extends SslHandler
    {
        private HTTPSHandler(SSLEngine engine)
        {
            super(engine);
        }

        @Override
        public void inboundBufferUpdated(ChannelHandlerContext ctx) throws Exception
        {
            ctx.inboundByteBuffer().markReaderIndex();
            int id = ctx.channel().id();

            if (sslChannels.contains(id)) {
                System.out.println(">> already SSL");
                // already ssl
                super.inboundBufferUpdated(ctx);
            } else {
                String s = ctx.inboundByteBuffer().toString(Charset.forName("UTF-8"));
                if (s.startsWith("CONNECT ")) {
                    // ssl detected
                    System.out.println("SSL ! : (channel id=" + id + ")" + s);
                    sslChannels.add(id);
                    ctx.inboundByteBuffer().clear();
                } else {
                    System.out.println("normal >> " + s);
                    ctx.inboundByteBuffer().resetReaderIndex();
                }
            }
        }
    }

    public void run() throws Exception
    {
        ServerBootstrap bootstrap = new ServerBootstrap();

        try {
            // config
            bootstrap
                .group(new NioEventLoopGroup(), new NioEventLoopGroup())
                .channel(NioServerSocketChannel.class)
                .childOption(ChannelOption.TCP_NODELAY, true)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .localAddress("0.0.0.0", port)
                .childHandler(new ChannelInitializer<SocketChannel>()
                {
                    @Override
                    public void initChannel(SocketChannel ch) throws Exception
                    {
                        // Create a default pipeline implementation.
                        ChannelPipeline p = ch.pipeline();

                        SSLEngine engine = createSSLEngine();
                        SslHandler httpsHandler = new HTTPSHandler(engine);
                        p.addLast("https", httpsHandler);

                        p.addLast(new ChannelInboundByteHandlerAdapter()
                        {
                            @Override
                            public void inboundBufferUpdated(ChannelHandlerContext ctx, ByteBuf in) throws Exception
                            {
                                String s = in.toString(Charset.forName("UTF-8"));

                                //ctx.inboundByteBuffer().clear();

                                System.out.println("AFTER::>> " + s);
                                ctx.inboundByteBuffer().clear();

                                //ctx.close();
                            }
                        });

                        // Uncomment the following line if you want HTTPS
                        //SSLEngine engine = SecureChatSslContextFactory.getServerContext().createSSLEngine();
                        //engine.setUseClientMode(false);
                        //p.addLast("ssl", new SslHandler(engine));

//                        p.addLast("decoder", new HttpRequestDecoder());
                        // Uncomment the following line if you don't want to handle HttpChunks.
                        //p.addLast("aggregator", new HttpObjectAggregator(1048576));
//                        p.addLast("encoder", new HttpResponseEncoder());
                        // Remove the following line if you don't want automatic content compression.
                        //p.addLast("deflater", new HttpContentCompressor());
//                        p.addLast("handler", new HttpSnoopServerHandler());
                    }
                })
            ;

            // bind
            final Channel channel = bootstrap.bind().sync().channel();

            System.out.println("> before closeFuture");
            channel.closeFuture().sync();
            System.out.println("> after closeFuture");

        } finally {
            System.out.println("> before shutdown");
            bootstrap.shutdown();
            System.out.println("> after shutdown");
        }
    }

    private SSLEngine createSSLEngine()
    {
        char[] passPhrase = "snoopy".toCharArray();

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
//            KeyStore trustStore = KeyStore.getInstance("JKS");

            keyStore.load(getClass().getResourceAsStream("mitm-cert.jks"), passPhrase);
//            trustStore.load(new FileInputStream(trustStoreFile), passPhrase);

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, passPhrase);

//            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
//            trustManagerFactory.init(trustStore);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(
                keyManagerFactory.getKeyManagers(),
                null /*trustManagerFactory.getTrustManagers()*/,
                null
            );


            SSLEngine serverEngine = context.createSSLEngine();
            serverEngine.setUseClientMode(false);
            serverEngine.setEnableSessionCreation(true);
            //serverEngine.setWantClientAuth(true);

            return serverEngine;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

//    /**
//     * Create a self-signed X.509 Certificate
//     *
//     * @param dn        the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
//     * @param pair      the KeyPair
//     * @param days      how many days from now the Certificate is valid for
//     * @param algorithm the signing algorithm, eg "SHA1withRSA"
//     */
//    X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
//        throws GeneralSecurityException, IOException
//    {
//        PrivateKey privateKey = pair.getPrivate();
//        X509CertInfo info = new X509CertInfo();
//        Date from = new Date();
//        Date to = new Date(from.getTime() + days * 86400000l);
//        CertificateValidity interval = new CertificateValidity(from, to);
//        BigInteger sn = new BigInteger(64, new SecureRandom());
//        X500Name owner = new X500Name(dn);
//
//        info.set(X509CertInfo.VALIDITY, interval);
//        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
//        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
//        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
//        info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
//        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
//        AlgorithmId algorithmId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
//        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithmId));
//
//        // Sign the cert to identify the algorithm that's used.
//        X509CertImpl cert = new X509CertImpl(info);
//        cert.sign(privateKey, algorithm);
//
//        // Update the algorithm, and resign.
//        algorithmId = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
//        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algorithmId);
//        cert = new X509CertImpl(info);
//        cert.sign(privateKey, algorithm);
//
//        return cert;
//    }
}
