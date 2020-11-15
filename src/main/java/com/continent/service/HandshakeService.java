
package com.continent.service;

import com.continent.engine.rc6.RC6_256_256Engine;
import com.continent.handler.HandshakePacketSplitter;
import com.continent.handler.client.ClientFirstPacketDecoder;
import com.continent.random.RandomDelegator;
import com.continent.random.RandomService;
import com.continent.random.SkeinRandom;
import com.google.common.base.Function;
import com.google.common.io.BaseEncoding;
import com.google.common.util.concurrent.*;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.*;
import io.netty.channel.*;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.ChannelGroupFuture;
import io.netty.channel.group.ChannelGroupFutureListener;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.*;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.util.concurrent.ScheduledFuture;
import io.netty.util.internal.PlatformDependent;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.NtruEncrypt;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SkeinDigest;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.io.MacOutputStream;
import org.bouncycastle.crypto.macs.SkeinMac;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.*;

/**
 * CPub, SPub session public keys
 *
 * 1. R + enc(H(DPub), R, CPub) + Tag + RandomTail -> S
 *    packet size: 32 + 2066 + 8
 *
 * 2. C <- R + enc(H(DPub), R, SPub) + enc(CPub, ServerIVSeed + ServerKey + ServerCYPHERSID) + enc(DPub, ServerSecurityCode + MAC(ServerSecurityCode, PACKET)) + Tag + RandomTail
 *    packet size: 32 + 2066 + 2062*2 + 2062 + 8
 *
 * 3. enc(SPub, ClientIVSeed + ClientKey + ClientCYPHERSID + ServerSecurityCode + ClientSecurityCode + RandomTimings) + Tag + RandomTail -> S
 *    packet size: 2062*3 + 8
 *
 * 4. C <- enc(CPub, ClientSecurityCode) + Tag + RandomTail
 *    packet size: 2062 + 8
 */
public class HandshakeService {

    public static final int FIRST_SERVER_PACKET_LENGTH = HandshakeService.publicKeyIVSize + HandshakeService.ntruPublicKeySize
                                                            + HandshakeService.ntruEncryptedChunkSize*HandshakeService.ntruServerChunks
                                                                + HandshakeService.ntruEncryptedChunkSize + HandshakeService.tagSize;

//    private final Logger log = NOPLogger.NOP_LOGGER;
    private final Logger log = LoggerFactory.getLogger(HandshakeService.class);

    private static final int IV_SEED_SIZE = 64;
    public static final int publicKeyIVSize = 32;
    private static final int securityCodeSize = 32;
    private static final int cipherIdSize = 2;
    
    public static final int ntruPublicKeySize = 2066;
    public static final int ntruDecryptedChunkSize = 247;
    public static final int ntruServerChunks = 2;
    public static final int ntruClientChunks = 3;
    public static final int ntruEncryptedChunkSize = 2062;
    public static final int tagSize = 8;
    
    private byte[] id;
    private byte[] pubKey;
    private byte[] encryptionKey;
    private byte[] privKey;
    
    private EncryptionPublicKey clientPublicKey;

    private EncryptionKeyPair clientKeyPair;
    private EncryptionKeyPair serverKeyPair;

    private List<Object> clientCiphers;
    private byte[] clientKeys;
    private List<Object> serverCiphers;
    private byte[] serverKeys;
    private byte[] serverIVSeed;
    private byte[] clientIVSeed;
    
    private ExecutorService executorService;
    
    private volatile SessionData clientSession;
    private RandomService randomService;
    private volatile SettableFuture<Void> handshakeFuture = SettableFuture.create();
    private CombinationsGenerator combinationsGenerator = new CombinationsGenerator();
    private byte[] serverSecurityCode;
    private byte[] clientSecurityCode;
    private volatile boolean clientInReconnection;

    private Map<byte[], byte[]> id2PubKey;
    
    private EventLoopGroup eventLoopGroup;
    
    private static final ConcurrentMap<Long, Boolean> authentificatedMacs = PlatformDependent.newConcurrentHashMap();

    private List<URI> urls;
    private ChannelGroup group;

    private final RandomDelegator randomDataGenerator;
    private final Map<SessionId, SessionData> serverSessionIds = new ConcurrentHashMap<SessionId, SessionData>();
    private Map<SessionId, SessionData> clientSessionIds;

    public HandshakeService(ExecutorService executorService, RandomService randomService, EventLoopGroup eventLoopGroup, String idStr, List<URI> urls, ChannelGroup group) {
        this.executorService = executorService;
        this.randomService = randomService;
        this.eventLoopGroup = eventLoopGroup;
        this.randomDataGenerator = randomService.createRandomDataGenerator();

        String[] parts = idStr.split(":");
        id = BaseEncoding.base64().decode(parts[0]);
        byte[] seed = BaseEncoding.base64().decode(parts[1]);
        SkeinRandom random = new SkeinRandom(seed, null, com.continent.engine.skein.SkeinDigest.SKEIN_256, 72);
        EncryptionKeyPair kp = generateKeyPair(new RandomDelegator(random), false);
        pubKey = kp.getPublic().getEncoded();
        privKey = kp.getPrivate().getEncoded();
        encryptionKey = calcPubKeyHash();
        this.urls = urls;
        this.group = group;
    }
    
    public HandshakeService(ExecutorService executorService, RandomService randomService, Map<SessionId, SessionData> clientSessionIds, Map<byte[], byte[]> id2PubKey) {
        this.executorService = executorService;
        this.randomService = randomService;
        this.clientSessionIds = clientSessionIds;
        this.id2PubKey = id2PubKey;
        this.randomDataGenerator = randomService.createRandomDataGenerator();
    }
    
    public ListenableFuture<Void> connect() {
        // skip if already in reconnection state
        if (clientInReconnection) {
            return null;
        }
        clientInReconnection = true;
        SettableFuture<Void> result = SettableFuture.create();
        connect(result);
        return result;
    }
    
    private void connect(final SettableFuture<Void> result) {
        handshakeFuture = SettableFuture.create();
        group.close().addListener(new ChannelGroupFutureListener() {
            @Override
            public void operationComplete(ChannelGroupFuture future) throws Exception {
                // discard handshake by timeout
                final ScheduledFuture<?> checkFuture = eventLoopGroup.schedule(new Runnable() {
                    @Override
                    public void run() {
                        handshakeFuture.cancel(false);
                    }
                }, randomService.getNonceGenerator().nextInt(15) + 15, TimeUnit.SECONDS);

                Futures.addCallback(handshakeFuture, new FutureCallback<Void>() {

                    @Override
                    public void onSuccess(Void res) {
                        result.set(null);
                        clientInReconnection = false;
                    }

                    @Override
                    public void onFailure(Throwable t) {
                        if (t instanceof WrongHandshakeResponse) {
                            result.setException(t);
                            clientInReconnection = false;
                            return;
                        }

                        log.error(t.getMessage(), t);
                        
                        checkFuture.cancel(false);
                        int delay = randomService.getNonceGenerator().nextInt(3000);
                        eventLoopGroup.schedule(new Runnable() {
                            @Override
                            public void run() {
                                connect(result);
                            }
                        }, delay, TimeUnit.MILLISECONDS);
                    }
                    
                }, MoreExecutors.directExecutor());
                
                int index = randomService.getNonceGenerator().nextInt(urls.size());
                final URI serverUri = urls.get(index);
                
                Bootstrap b = new Bootstrap();
                b.group(eventLoopGroup)
                 .channel(NioSocketChannel.class)
                 .handler(new ChannelInitializer<Channel>() {
                     @Override
                     protected void initChannel(final Channel ch) throws Exception {
                         if (serverUri.getScheme().equals("https")) {
                             SslContextBuilder sslContextBuilder = SslContextBuilder.forClient();
                             ApplicationProtocolConfig apn = new ApplicationProtocolConfig(
                                     Protocol.ALPN, SelectorFailureBehavior.CHOOSE_MY_LAST_PROTOCOL,
                                     SelectedListenerFailureBehavior.ACCEPT, Arrays.asList("h2", "http/1.1"));
                             sslContextBuilder.trustManager(InsecureTrustManagerFactory.INSTANCE);
                             sslContextBuilder.applicationProtocolConfig(apn);
                             
                             SslContext sslContext = sslContextBuilder.build();
                             SSLEngine sslEngine = sslContext.newEngine(ch.alloc(), serverUri.getHost(), serverUri.getPort());
                             
                             SslHandler sslHandler = new SslHandler(sslEngine);
                             ch.pipeline().addLast(sslHandler);
                             ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                                 
                                 volatile boolean sslInitDone;
                                 
                                 @Override
                                 public void channelActive(ChannelHandlerContext ctx) throws Exception {
                                     if (sslInitDone) {
                                         super.channelActive(ctx);
                                     }
                                 }
                                 
                                 @Override
                                 public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
                                     if (!sslInitDone && (evt instanceof SslHandshakeCompletionEvent)) {
                                         SslHandshakeCompletionEvent e = (SslHandshakeCompletionEvent) evt;
                                         if (e.isSuccess()) {
                                             sslInitDone = true;

                                             log.info("HTTPS handshake completed {}", serverUri);

                                             ch.pipeline().addLast(new HandshakePacketSplitter(randomService));
                                             ch.pipeline().addLast(new ClientFirstPacketDecoder(HandshakeService.this));

                                             ctx.fireChannelActive();
                                             
                                         } else {
                                             log.error("Can't connect to " + serverUri.getHost() + ":" + serverUri.getPort(), e.cause());
                                         }
                                     }

                                     super.userEventTriggered(ctx, evt);
                                 }

                             });
                         } else {
                             ch.pipeline().addLast(new HandshakePacketSplitter(randomService));
                             ch.pipeline().addLast(new ClientFirstPacketDecoder(HandshakeService.this));
                         }
                     }
                 });

                log.info("Connecting to {}", serverUri);
                
                ChannelFuture connectFuture = b.connect(serverUri.getHost(), serverUri.getPort());
                connectFuture.addListener(new ChannelFutureListener() {
                    @Override
                    public void operationComplete(ChannelFuture future) {
                        if (!future.isSuccess()) {
                            handshakeFuture.setException(new IllegalStateException("Can't connect to " + serverUri, future.cause()));
                        } else {
                            log.info("connected to {}", serverUri);
                        }
                    }
                });
                connectFuture.channel().closeFuture().addListener(new ChannelFutureListener() {
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception {
                        handshakeFuture.setException(new IllegalStateException("Channel has been closed!"));
                    }
                });
            }
        });
    }
    
    private String prettyDump(byte[] seedBytes) {
        ByteBuf b = Unpooled.wrappedBuffer(seedBytes);
        try {
            return ByteBufUtil.prettyHexDump(b);
        } finally {
            b.release();
        }
    }

    public ListenableFuture<ByteBuf> createClientToServer1stPacket(final ChannelHandlerContext ctx) throws IOException {
        ListenableFuture<EncryptionKeyPair> keyPairFuture = generateKeyPair();
        return Futures.transform(keyPairFuture, new Function<EncryptionKeyPair, ByteBuf>() {
            @Override
            public ByteBuf apply(EncryptionKeyPair ntruKeyPair) {
                clientKeyPair = ntruKeyPair;
                byte[] publicKey = clientKeyPair.getPublic().getEncoded();
                
                ByteBuf result = ctx.alloc().buffer();
                try {            
                    addEncryptedPublicKey(publicKey, result);
                } catch (IOException e1) {
                    close(ctx);
                    log.error(e1.getMessage(), e1);
                    return null;
                }

                addTagAndRandomTail(result);
                return result;
            }
        }, MoreExecutors.directExecutor());
    }

    public ListenableFuture<ByteBuf> createServerToClient1stPacket(ByteBuf in, final ChannelHandlerContext ctx, Function<Integer, Void> skippedBytesConsumer) throws IOException {
        log.debug("1st packet received. size: {}", in.readableBytes());
        
        int startIndex = in.readerIndex();
        byte[] iv = new byte[publicKeyIVSize];
        in.readBytes(iv);
        
        if (log.isDebugEnabled()) {
            log.debug("1st packet iv\n{}", prettyDump(iv));
        }
        
        byte[] encryptedClientPublicKey = new byte[ntruPublicKeySize];
        in.readBytes(encryptedClientPublicKey);
        
        if (log.isDebugEnabled()) {
            log.debug("1st packet encrypted public key\n{}", prettyDump(encryptedClientPublicKey));
        }
        
        byte[] tag = readTagAndGuessId(in, startIndex, "1st packet", ctx.channel());
        if (tag == null) {
            ByteBuf buf = createRehandshakePacket(ctx);
            return Futures.immediateFuture(buf);
        }
        
        long tagId = ByteBuffer.wrap(truncateTag(tag)).getLong();
        if (authentificatedMacs.putIfAbsent(tagId, Boolean.TRUE) != null) {
            close(ctx);
            log.error("Someone attempts to replay previous message. Tag: {} Channel: {}", tagId, ctx.channel());
            return Futures.immediateFuture(null);
        }

        int randomTailLength = readRandomTailLength(tag);
        skippedBytesConsumer.apply(randomTailLength);
        
        log.debug("1st packet random tail size: {}", randomTailLength);

        try {
            clientPublicKey = decryptPublicKey(iv, encryptedClientPublicKey);
        } catch (Exception e) {
            log.error("Unable to decryptWithPassword public key. Tag: {} Channel: {}", tagId, ctx.channel());
            ByteBuf buf = createRehandshakePacket(ctx);
            return Futures.immediateFuture(buf);
        }

        ListenableFuture<EncryptionKeyPair> keyPairFuture = generateKeyPair();
        ListenableFuture<ByteBuf> async = Futures.transformAsync(keyPairFuture, new AsyncFunction<EncryptionKeyPair, ByteBuf>() {
            @Override
            public ListenableFuture<ByteBuf> apply(EncryptionKeyPair ntruKeyPair) throws Exception {
                serverKeyPair = ntruKeyPair;
                
                byte[] publicKey = ntruKeyPair.getPublic().getEncoded();

                final ByteBuf result = ctx.alloc().buffer();
                try {
                    addEncryptedPublicKey(publicKey, result);
                } catch (IOException e1) {
                    close(ctx);
                    log.error(e1.getMessage(), e1);
                    return Futures.immediateFuture(null);
                }

                byte[] ciphersId = new byte[cipherIdSize];
                randomService.getKeyGenerator().nextBytes(ciphersId);
                serverCiphers = combinationsGenerator.getCiphers(ciphersId, 3);

                serverIVSeed = new byte[IV_SEED_SIZE];
                randomService.getKeyGenerator().nextBytes(serverIVSeed);

                serverKeys = generateKeysData();
                byte[] keysDataJoined = join(serverIVSeed, serverKeys, ciphersId);

                if (log.isDebugEnabled()) {
                    log.debug("sent iv seed {}\n {}", serverIVSeed.length, prettyDump(serverIVSeed));
                    log.debug("sent keys {}\n {}", serverKeys.length, prettyDump(serverKeys));
                    log.debug("sent ciphers id {}\n {}", ciphersId.length, prettyDump(ciphersId));
                }

                ListenableFuture<ByteBuf> encryptedServerKeysFuture = encryptCipherKeys(keysDataJoined, clientPublicKey, ctx);
                return Futures.transform(encryptedServerKeysFuture, new Function<ByteBuf, ByteBuf>() {
                    @Override
                    public ByteBuf apply(ByteBuf encryptedServerKeys) {
                        serverSecurityCode = new byte[securityCodeSize];
                        randomService.getKeyGenerator().nextBytes(serverSecurityCode);

                        if (log.isDebugEnabled()) {
                            log.debug("sent uncrypted server security code\n{}", prettyDump(serverSecurityCode));
                        }
                        
                        result.writeBytes(encryptedServerKeys);
                        encryptedServerKeys.release();
                        
                        ByteBuf securityHashBuf = result.slice();
                        byte[] securityMac = calcMac(securityHashBuf, serverSecurityCode);
                        
                        if (log.isDebugEnabled()) {
                            log.debug("sent uncrypted server security mac\n{}", prettyDump(securityMac));
                        }
                        
                        byte[] securityData = join(serverSecurityCode, securityMac);
                        byte[] encryptedSecurityData = CryptoService.encryptCipherKeys(securityData, new EncryptionPublicKey(pubKey), randomService.getKeyGenerator());
                        burn(securityData);
                        result.writeBytes(encryptedSecurityData);
                        
                        if (log.isDebugEnabled()) {
                            log.debug("sent encrypted server security data\n{}", prettyDump(encryptedSecurityData));
                        }
                        
                        addTagAndRandomTail(result);
                        return result;
                    }
                }, executorService);
            }
        }, MoreExecutors.directExecutor());
        Futures.addCallback(async, new FutureCallback<ByteBuf>() {
            @Override
            public void onSuccess(ByteBuf result) {
            }

            @Override
            public void onFailure(Throwable e) {
                log.error("Can't generate key", e);
                close(ctx);
            }
        }, MoreExecutors.directExecutor());
        return async;
    }

    private ByteBuf createRehandshakePacket(final ChannelHandlerContext ctx) {
        int randomLength = getRandomNumberInRange(randomDataGenerator, HandshakeService.FIRST_SERVER_PACKET_LENGTH, HandshakeService.FIRST_SERVER_PACKET_LENGTH*2);
        ByteBuf buf = ctx.alloc().buffer(randomLength);
        addRandomTail(buf, randomLength);
        ctx.executor().schedule(new Runnable() {
            @Override
            public void run() {
                ctx.close();
            }
        }, getRandomNumberInRange(randomDataGenerator, 2, 10), TimeUnit.SECONDS);
        return buf;
    }

    private int getRandomNumberInRange(RandomDelegator randomDataGenerator, int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("max must be greater than min");
        }

        return randomDataGenerator.nextInt((max - min) + 1) + min;
    }
    
    private ListenableFuture<EncryptionKeyPair> generateKeyPair() {
        return Futures.submitAsync(new AsyncCallable<EncryptionKeyPair>() {
            @Override
            public ListenableFuture<EncryptionKeyPair> call() throws Exception {
                return Futures.immediateFuture(generateKeyPair(randomService.getKeyGenerator(), true));
            }
        }, executorService);
    }

    public static void main(String[] args) throws ExecutionException, InterruptedException {
        HandshakeService hs = new HandshakeService(Executors.newSingleThreadExecutor(), new RandomService(12, 12), null, null);
        ListenableFuture<EncryptionKeyPair> s = hs.generateKeyPair();
        EncryptionKeyPair t = s.get();
        System.out.println(t.getPublic().getEncoded().length);
        System.out.println(t.getPrivate().getEncoded().length);
    }

    private EncryptionKeyPair generateKeyPair(Random random, boolean multiThreaded) {
        try {
            Method method = NtruEncrypt.class.getDeclaredMethod("generateKeyPair", Random.class, boolean.class);
            method.setAccessible(true);
            return (EncryptionKeyPair) method.invoke(CryptoService.NTRU, random, multiThreaded);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    
    public ListenableFuture<ByteBuf> createClientToServer2ndPacket(ByteBuf in, ChannelHandlerContext ctx, Function<Integer, Void> skippedBytesConsumer) {
        log.debug("2nd packet received. size: {}", in.readableBytes());
        
        int startIndex = in.readerIndex();
        byte[] publicKeyIV = new byte[publicKeyIVSize];
        in.readBytes(publicKeyIV);
        
        if (log.isDebugEnabled()) {
            log.debug("2nd packet iv {}\n{}", publicKeyIV.length, prettyDump(publicKeyIV));
        }
        
        byte[] encryptedServerPublicKey = new byte[ntruPublicKeySize];
        in.readBytes(encryptedServerPublicKey);

        if (log.isDebugEnabled()) {
            log.debug("2nd packet encrypted public key {}\n{}", encryptedServerPublicKey.length, prettyDump(encryptedServerPublicKey));
        }
        
        byte[] encryptedServerKeys = new byte[ntruEncryptedChunkSize*ntruServerChunks];
        in.readBytes(encryptedServerKeys);

        if (log.isDebugEnabled()) {
            log.debug("2nd packet encrypted keys data {}\n{}", encryptedServerKeys.length, prettyDump(encryptedServerKeys));
        }
        
        int encryptedSecurityDataIndex = in.readerIndex();
        
        byte[] encryptedSecurityData = new byte[ntruEncryptedChunkSize];
        in.readBytes(encryptedSecurityData);
        
        if (log.isDebugEnabled()) {
            log.debug("2nd packet encrypted security data {}\n{}", encryptedSecurityData.length, prettyDump(encryptedSecurityData));
        }
        
        byte[] tag = readAndCheckTag(in, startIndex, "2nd packet", ctx.channel());
        if (tag == null) {
            WrongHandshakeResponse ex = new WrongHandshakeResponse("Wrong server response. Channel: " + ctx.channel());
            handshakeFuture.setException(ex);
            close(ctx);
            log.error("Wrong server response. Channel: {}", ctx.channel());
            return Futures.immediateFailedFuture(ex);
        }

        int randomTailLength = readRandomTailLength(tag);
        skippedBytesConsumer.apply(randomTailLength);
        
        log.debug("2nd packet random tail size: {}", randomTailLength);
        
        byte[] decryptedSecurityData = CryptoService.NTRU.decrypt(encryptedSecurityData,
                new EncryptionKeyPair(new EncryptionPrivateKey(privKey), new EncryptionPublicKey(pubKey)));
        serverSecurityCode = Arrays.copyOf(decryptedSecurityData, 32);
        byte[] securityMac = Arrays.copyOfRange(decryptedSecurityData, 32, 64);

        if (log.isDebugEnabled()) {
            log.debug("2nd packet uncrypted server security code\n{}", prettyDump(serverSecurityCode));
            log.debug("2nd packet uncrypted server security mac\n{}", prettyDump(securityMac));
        }
        
        ByteBuf securityTag = in.slice(startIndex, encryptedSecurityDataIndex - startIndex);
        byte[] calcSecurityMac = calcMac(securityTag, serverSecurityCode);

        if (!Arrays.equals(calcSecurityMac, securityMac)) {
            IllegalStateException ex = new IllegalStateException("Wrong security mac on channel: " + ctx.channel());
            handshakeFuture.setException(ex);
            close(ctx);
            return Futures.immediateFailedFuture(ex);
        }
        
        EncryptionPublicKey serverPublicKey;
        try {
            serverPublicKey = decryptPublicKey(publicKeyIV, encryptedServerPublicKey);
        } catch (Exception e) {
            IllegalStateException ex = new IllegalStateException("Unable to decryptWithPassword server key on channel: " + ctx.channel(), e);
            handshakeFuture.setException(ex);
            close(ctx);
            return Futures.immediateFailedFuture(ex);
        }

        final byte[] keysData;
        try {
            keysData = CryptoService.decryptCipherKeys(new ByteArrayInputStream(encryptedServerKeys), clientKeyPair);
        } catch (Exception e) {
            close(ctx);
            log.error("Can't decrypt server keys data", e);
            return null;
        }

        ByteBuf serverKeysBuf = Unpooled.wrappedBuffer(keysData);
        serverIVSeed = new byte[IV_SEED_SIZE];
        serverKeysBuf.readBytes(serverIVSeed);
        serverKeys = new byte[CryptoService.MAX_KEYS_DATA_SIZE];
        serverKeysBuf.readBytes(serverKeys);
        byte[] serverCiphersId = new byte[cipherIdSize];
        serverKeysBuf.readBytes(serverCiphersId);
        serverKeysBuf.release();

        burn(keysData);

        if (log.isDebugEnabled()) {
            log.debug("2nd packet uncrypted server keys {}\n{}", keysData.length, prettyDump(keysData));
            log.debug("2nd packet uncrypted server ciphers id {}\n{}", serverCiphersId.length, prettyDump(serverCiphersId));
        }
        
        serverCiphers = combinationsGenerator.getCiphers(serverCiphersId, 3);
        if (serverCiphers == null) {
            IllegalStateException ex = new IllegalStateException("Unable to decryptWithPassword data. Data length: " + in.writerIndex() + " Channel: " + ctx.channel());
            close(ctx);
            log.error("Can't decryptWithPassword data. Data length: {}, on channel: {}", in.writerIndex(), ctx.channel());
            return Futures.immediateFailedFuture(ex);
        }

        byte[] ciphersId = new byte[cipherIdSize];
        randomService.getKeyGenerator().nextBytes(ciphersId);
        clientCiphers = combinationsGenerator.getCiphers(ciphersId, 3);

        clientIVSeed = new byte[IV_SEED_SIZE];
        randomService.getKeyGenerator().nextBytes(clientIVSeed);

        clientKeys = generateKeysData();
        
        clientSecurityCode = new byte[securityCodeSize];
        randomService.getKeyGenerator().nextBytes(clientSecurityCode);

        byte[] keysDataJoined = join(clientIVSeed, clientKeys, ciphersId, serverSecurityCode, clientSecurityCode, new byte[] {20, 40});

        if (log.isDebugEnabled()) {
            log.debug("sent iv seed {}\n {}", clientIVSeed.length, prettyDump(clientIVSeed));
            log.debug("sent keys {}\n {}", clientKeys.length, prettyDump(clientKeys));
            log.debug("sent ciphers id {}\n {}", ciphersId.length, prettyDump(ciphersId));
            log.debug("sent server security code {}\n {}", serverSecurityCode.length, prettyDump(serverSecurityCode));
            log.debug("sent client security code {}\n {}", clientSecurityCode.length, prettyDump(clientSecurityCode));
        }

        ListenableFuture<ByteBuf> future = encryptCipherKeys(keysDataJoined, serverPublicKey, ctx);
        return Futures.transform(future, new Function<ByteBuf, ByteBuf>() {
            @Override
            public ByteBuf apply(ByteBuf encryptedClientKeys) {
                addTagAndRandomTail(encryptedClientKeys);
                return encryptedClientKeys;
            }
        }, MoreExecutors.directExecutor());
    }

    public ListenableFuture<ByteBuf> createServerToClient2ndPacket(ByteBuf in, final ChannelHandlerContext ctx, Function<Integer, Void> skippedBytesConsumer) {
        log.debug("2nd packet received. size: {}", in.readableBytes());

        int startIndex = in.readerIndex();
        
        ByteBuf keysIn = in.slice(in.readerIndex(), ntruEncryptedChunkSize*ntruClientChunks);
        in.skipBytes(ntruEncryptedChunkSize*ntruClientChunks);
        byte[] tag = readAndCheckTag(in, startIndex, "2nd packet", ctx.channel());
        if (tag == null) {
            close(ctx);
            return Futures.immediateFuture(null);
        }
        
        int randomTailLength = readRandomTailLength(tag);
        skippedBytesConsumer.apply(randomTailLength);
        
        log.debug("2nd packet random tail size: {}", randomTailLength);
        
        final byte[] clientKeyData;
        try {
            clientKeyData = CryptoService.decryptCipherKeys(new ByteBufInputStream(keysIn), serverKeyPair);
        } catch (Exception e) {
            close(ctx);
            log.error("Can't decrypt client keys data", e);
            return null;
        }

        ByteBuf clientKeyDataBuf = Unpooled.wrappedBuffer(clientKeyData);
        clientIVSeed = new byte[IV_SEED_SIZE];
        clientKeyDataBuf.readBytes(clientIVSeed);
        final byte[] keyData = new byte[CryptoService.MAX_KEYS_DATA_SIZE];
        clientKeyDataBuf.readBytes(keyData);
        byte[] ciphersId = new byte[cipherIdSize];
        clientKeyDataBuf.readBytes(ciphersId);
        byte[] inServerSecurityCode = new byte[securityCodeSize];
        clientKeyDataBuf.readBytes(inServerSecurityCode);
        clientSecurityCode = new byte[securityCodeSize];
        clientKeyDataBuf.readBytes(clientSecurityCode);
        final byte[] randomTimeouts = new byte[2];
        clientKeyDataBuf.readBytes(randomTimeouts);
        clientKeyDataBuf.release();

        burn(clientKeyData);

        if (log.isDebugEnabled()) {
            log.debug("2nd packet keys data {}\n{}", clientKeyData.length, prettyDump(clientKeyData));
            log.debug("2nd packet uncrypted ciphers id {}\n{}", ciphersId.length, prettyDump(ciphersId));
            log.debug("2nd packet uncrypted server security code {}\n{}", inServerSecurityCode.length, prettyDump(inServerSecurityCode));
            log.debug("2nd packet uncrypted client security code {}\n{}", clientSecurityCode.length, prettyDump(clientSecurityCode));
        }
        
        if (!Arrays.equals(inServerSecurityCode, serverSecurityCode)) {
            close(ctx);
            log.error("Wrong security code on channel: {}", ctx.channel());
            return Futures.immediateFuture(null);
        }
        
        final List<Object> clientCiphers = combinationsGenerator.getCiphers(ciphersId, 3);
        if (clientCiphers == null) {
            close(ctx);
            log.error("Can't decryptWithPassword data. Data length: {} on channel: {}", in.writerIndex(), ctx.channel());
            return null;
        }
        
        return Futures.submitAsync(new AsyncCallable<ByteBuf>() {
            @Override
            public ListenableFuture<ByteBuf> call() throws Exception {
                ByteBuf buf = ctx.alloc().buffer();
                
                byte[] encryptedClientSecurityCode = CryptoService.NTRU.encrypt(clientSecurityCode, clientPublicKey);
                buf.writeBytes(encryptedClientSecurityCode);
                
                addTagAndRandomTail(buf);
                
                SessionData data = new SessionData(keyData, serverKeys, clientCiphers, serverCiphers, randomTimeouts);

                RandomGenerator clientRandomGenerator = new SkeinRandom(clientSecurityCode, null, com.continent.engine.skein.SkeinDigest.SKEIN_256, 72);
                data.setClientSessionGenerator(clientRandomGenerator);
                RandomGenerator serverRandomGenerator = new SkeinRandom(serverSecurityCode, null, com.continent.engine.skein.SkeinDigest.SKEIN_256, 72);
                data.setServerSessionGenerator(serverRandomGenerator);
                RandomGenerator ivClientRandomGenerator = new SkeinRandom(clientIVSeed, null, com.continent.engine.skein.SkeinDigest.SKEIN_256, 72);
                data.setClientIVGenerator(ivClientRandomGenerator);
                RandomGenerator ivServerRandomGenerator = new SkeinRandom(serverIVSeed, null, com.continent.engine.skein.SkeinDigest.SKEIN_256, 72);
                data.setServerIVGenerator(ivServerRandomGenerator);

                for (int i = 0; i < 100; i++) {
                    byte[] sessionId = new byte[SessionId.SIZE];
                    clientRandomGenerator.nextBytes(sessionId);
                    byte[] iv = new byte[CryptoService.MAX_IV_SIZE];
                    ivClientRandomGenerator.nextBytes(iv);
                    clientSessionIds.put(new SessionId(sessionId), new SessionData(data, iv));
                }

                String serverCiphersString = HandshakeService.toString(serverCiphers);
                log.debug("server ciphers: {}", serverCiphersString);
                String clientCiphersString = HandshakeService.toString(clientCiphers);
                log.debug("client ciphers: {}", clientCiphersString);
                return Futures.immediateFuture(buf);
            }
        }, executorService);
    }

    private static String toString(List<Object> ciphers) {
        StringBuilder str = new StringBuilder();
        for (Object chiper : ciphers) {
            if (chiper instanceof BlockCipher) {
                str.append(((BlockCipher)chiper).getAlgorithmName()).append(", ");
            }
            if (chiper instanceof StreamCipher) {
                str.append(((StreamCipher)chiper).getAlgorithmName()).append(", ");
            }
        }
        return str.toString();
    }

    private int readRandomTailLength(byte[] tag) {
//        byte[] packetLengthBytes = Arrays.copyOfRange(tag, 24, 32);
//        SplittableRandom random = new SplittableRandom(ByteBuffer.wrap(packetLengthBytes).getLong());
//        return random.nextInt(5000);
        byte[] packetLengthBytes = Arrays.copyOfRange(tag, 30, 32);
        int randomTailLength = toUnsignedInt(ByteBuffer.wrap(packetLengthBytes).getShort()) % 5000;
        return randomTailLength;
    }
    
    private static int toUnsignedInt(short x) {
        return ((int) x) & 0xffff;
    }
        
    public int handleLastPacket(ByteBuf in, ChannelHandlerContext ctx) {
        int startIndex = in.readerIndex();
        
        log.debug("Last packet received. size: {}", in.readableBytes());
        
        byte[] encryptedSecurityCode = new byte[ntruEncryptedChunkSize];
        in.readBytes(encryptedSecurityCode);
        
        byte[] tag = readAndCheckTag(in, startIndex, "Last packet", ctx.channel());
        if (tag == null) {
            handshakeFuture.setException(new IllegalStateException("Wrong tag on channel: " + ctx.channel()));
            close(ctx);
            return 0;
        }
        
        byte[] inClientSecurityCode = CryptoService.NTRU.decrypt(encryptedSecurityCode, clientKeyPair);
        
        if (!Arrays.equals(inClientSecurityCode, clientSecurityCode)) {
            handshakeFuture.setException(new IllegalStateException("Wrong security code on channel: " + ctx.channel()));
            close(ctx);
            return 0;
        }
        
        if (serverCiphers == null) {
            handshakeFuture.setException(new IllegalStateException("Can't decryptWithPassword data. Data length: " + in.writerIndex() + " on channel: " + ctx.channel()));
            close(ctx);
            return 0;
        }
        
        String serverCiphersString = toString(serverCiphers);
        log.info("server ciphers: " + serverCiphersString);
        String clientCiphersString = toString(clientCiphers);
        log.info("client ciphers: " + clientCiphersString);

        clientSession = new SessionData(clientKeys, serverKeys, clientCiphers, serverCiphers, new byte[] {});

        RandomGenerator clientRandomGenerator = new SkeinRandom(clientSecurityCode, null, com.continent.engine.skein.SkeinDigest.SKEIN_256, 72);
        clientSession.setClientSessionGenerator(clientRandomGenerator);
        RandomGenerator serverRandomGenerator = new SkeinRandom(serverSecurityCode, null, com.continent.engine.skein.SkeinDigest.SKEIN_256, 72);
        clientSession.setServerSessionGenerator(serverRandomGenerator);
        RandomGenerator ivClientRandomGenerator = new SkeinRandom(clientIVSeed, null, com.continent.engine.skein.SkeinDigest.SKEIN_256, 72);
        clientSession.setClientIVGenerator(ivClientRandomGenerator);
        RandomGenerator ivServerRandomGenerator = new SkeinRandom(serverIVSeed, null, com.continent.engine.skein.SkeinDigest.SKEIN_256, 72);
        clientSession.setServerIVGenerator(ivServerRandomGenerator);

        handshakeFuture.set(null);
        close(ctx);
        return readRandomTailLength(tag);
    }

    public void close(final ChannelHandlerContext ctx) {
        ctx.executor().schedule(new Runnable() {
            @Override
            public void run() {
                ctx.close();
            }
        }, randomDataGenerator.nextInt(1000), TimeUnit.MILLISECONDS);
    }

    private byte[] generateKeysData() {
        byte[] keyData = new byte[CryptoService.MAX_KEYS_DATA_SIZE];
        randomService.getKeyGenerator().nextBytes(keyData);
        return keyData;
    }
    
    private byte[] readTagAndGuessId(ByteBuf in, int startIndex, String logPrefix, Channel channel) {
        int endIndex = in.readerIndex();

        byte[] truncatedTag = new byte[tagSize];
        in.readBytes(truncatedTag);
        
        if (log.isDebugEnabled()) {
            log.debug(logPrefix + " tag\n{}", prettyDump(truncatedTag));
        }
        
        ByteBuf tagBuf = in.slice(startIndex, endIndex - startIndex);
        tagBuf.markReaderIndex();
        
        for (byte[] id : id2PubKey.keySet()) {
            byte[] tag = calcMac(tagBuf, id);
            
            byte[] calcTruncatedTag = truncateTag(tag);
            if (Arrays.equals(calcTruncatedTag, truncatedTag)) {
                this.id = id;
                pubKey = id2PubKey.get(id);
                encryptionKey = calcPubKeyHash();
                return tag;
            }  
            tagBuf.resetReaderIndex();
        }

        tagBuf.resetReaderIndex();
        log.error("Handshake packet couldn't be decrypted. Wrong auth id used. Channel: {}\n{}", channel, ByteBufUtil.prettyHexDump(tagBuf));
        return null;
    }
    
    private byte[] readAndCheckTag(ByteBuf in, int startIndex, String logPrefix, Channel channel) {
        int endIndex = in.readerIndex();

        byte[] truncatedTag = new byte[tagSize];
        in.readBytes(truncatedTag);
        
        if (log.isDebugEnabled()) {
            log.debug(logPrefix + " tag\n{}", prettyDump(truncatedTag));
        }
        
        ByteBuf tagBuf = in.slice(startIndex, endIndex - startIndex);
        byte[] tag = calcMac(tagBuf, id);
        
        byte[] calcTruncatedTag = truncateTag(tag);
        if (!Arrays.equals(calcTruncatedTag, truncatedTag)) {
            tagBuf.resetReaderIndex();
            log.error("Wrong tag on channel: {}", channel);
            return null;
        }
        return tag;
    }

    private byte[] calcPubKeyHash() {
        SkeinDigest keyHash = new SkeinDigest(SkeinDigest.SKEIN_256, 256);
        keyHash.update(pubKey, 0, pubKey.length);
        byte[] encryptionKey = new byte[32];
        keyHash.doFinal(encryptionKey, 0);
        return encryptionKey;
    }

    private EncryptionPublicKey decryptPublicKey(byte[] iv, byte[] encryptedClientPublicKey) throws IOException {
        StreamCipher bufferedCipher = new CFBBlockCipher(new RC6_256_256Engine(), 16*8);
        bufferedCipher.init(false, new ParametersWithIV(new KeyParameter(encryptionKey), iv));

        ByteArrayOutputStream bbos = new ByteArrayOutputStream(ntruPublicKeySize);
        CipherOutputStream os = new CipherOutputStream(bbos, bufferedCipher);
        os.write(encryptedClientPublicKey);
        os.close();
        return new EncryptionPublicKey(bbos.toByteArray());
    }

    public SessionData getClientSession(byte[] sessionId) {
        return clientSessionIds.get(new SessionId(sessionId));
    }

    public boolean checkClientSession(byte[] sessionId) {
        SessionData data = clientSessionIds.remove(new SessionId(sessionId));
        if (data == null) {
            return false;
        }
        return true;
    }

    public SessionData getServerSession(byte[] sessionId) {
        return serverSessionIds.get(new SessionId(sessionId));
    }

    public void generateNewClientSessionId(SessionData data) {
        byte[] id = new byte[SessionId.SIZE];
        byte[] iv = new byte[CryptoService.MAX_IV_SIZE];
        data.getLock().lock();
        data.getClientSessionGenerator().nextBytes(id);
        data.getClientIVGenerator().nextBytes(iv);
        data.getLock().unlock();
        clientSessionIds.put(new SessionId(id), new SessionData(data, iv));
    }

    public void generateNewServerSessionId() {
        byte[] id = new byte[SessionId.SIZE];
        byte[] iv = new byte[CryptoService.MAX_IV_SIZE];
        clientSession.getLock().lock();
        clientSession.getServerSessionGenerator().nextBytes(id);
        clientSession.getServerIVGenerator().nextBytes(iv);
        clientSession.getLock().unlock();
        serverSessionIds.put(new SessionId(id), new SessionData(clientSession, iv));
    }

    public boolean checkServerSession(byte[] sessionId) {
        SessionData data = serverSessionIds.remove(new SessionId(sessionId));
        if (data == null) {
            return false;
        }
        return true;
    }

    private byte[] calcMac(ByteBuf in, byte[] key) {
        SkeinMac tagMac = new SkeinMac(SkeinMac.SKEIN_256, 256);
        tagMac.init(new KeyParameter(key));
        
        MacOutputStream os = new MacOutputStream(tagMac);
        try {
            in.readBytes(os, in.readableBytes());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return os.getMac();
    }
    
    private byte[] join(byte[]... arrays) {
        int len = 0;
        for (byte[] bs : arrays) {
            len += bs.length;
        }
        byte[] joinedArray = new byte[len];
        int index = 0;
        for (byte[] bs : arrays) {
            System.arraycopy(bs, 0, joinedArray, index, bs.length);
            index += bs.length;
        }
        return joinedArray;
    }
    
    private void addRandomTail(ByteBuf output, int randomLength) {
        if (randomLength > 0) {
            for (int i = 0; i < randomLength; ) {
                for (int rnd = randomDataGenerator.nextInt(),
                        n = Math.min(randomLength - i, Integer.SIZE/Byte.SIZE);
                        n-- > 0; rnd >>= Byte.SIZE) {
                    output.writeByte((byte)rnd);
                    i++;
                }
            }
        }
    }
    
    private void addTagAndRandomTail(ByteBuf result) {
        ByteBuf hashBuf = result.slice();
        byte[] tag = calcMac(hashBuf, id);
        
        byte[] truncatedTag = truncateTag(tag);
        result.writeBytes(truncatedTag);

        if (log.isDebugEnabled()) {
            log.debug("sent tag\n{}", prettyDump(truncatedTag));
        }
        
        int randomTailLength = readRandomTailLength(tag);
        if (randomTailLength > 0) {
            addRandomTail(result, randomTailLength);
            if (log.isDebugEnabled()) {
                log.debug("sent random tail {}\n{}", randomTailLength, ByteBufUtil.prettyHexDump(result.slice(result.writerIndex() - randomTailLength, randomTailLength)));
            }
//            log.info("sent random tail {}", randomTailLength);
        }
        
        log.debug("sent packet size: {}", result.writerIndex());
    }

    private byte[] truncateTag(byte[] tag) {
        return Arrays.copyOf(tag, tagSize);
    }

    private void addEncryptedPublicKey(byte[] publicKey, ByteBuf result) throws IOException {
        byte[] iv = new byte[publicKeyIVSize];
        randomService.getNonceGenerator().nextBytes(iv);
        result.writeBytes(iv);
                
        if (log.isDebugEnabled()) {
            log.debug("sent packet iv\n{}", prettyDump(iv));
        }
        
        // TODO choose cipher in random way
        StreamCipher bufferedCipher = new CFBBlockCipher(new RC6_256_256Engine(), 16*8);
        bufferedCipher.init(true, new ParametersWithIV(new KeyParameter(encryptionKey), iv));
        
        int startIndex = result.writerIndex();
        ByteBufOutputStream bbos = new ByteBufOutputStream(result);
        CipherOutputStream os = new CipherOutputStream(bbos, bufferedCipher);
        os.write(publicKey);
        os.close();
        
        if (log.isDebugEnabled()) {
            log.debug("sent encrypted public key\n{}", ByteBufUtil.prettyHexDump(result.slice(startIndex, result.writerIndex() - startIndex)));
        }
    }
    
    // TODO use in encryption
    public EncryptionPublicKey readPublicKey(ByteBuf in, ChannelHandlerContext ctx) {
        byte[] serverPublicKey = new byte[ntruPublicKeySize];
        serverPublicKey[0] = 0x02;
        serverPublicKey[1] = (byte) 0xe7;
        serverPublicKey[2] = 0x08;
        serverPublicKey[3] = 0x00;
        in.readBytes(serverPublicKey, 4, ntruPublicKeySize - 4);
        
        // consume random tail
        in.readerIndex(in.writerIndex());
        
        return new EncryptionPublicKey(serverPublicKey);
    }

    
    private ListenableFuture<ByteBuf> encryptCipherKeys(final byte[] keysDataJoined, final EncryptionPublicKey remotePublicKey,
            final ChannelHandlerContext ctx) {
        // executed in separate executorService because NTRU encryption is a long-running task
        return Futures.submitAsync(new AsyncCallable<ByteBuf>() {
            @Override
            public ListenableFuture<ByteBuf> call() throws Exception {
                ByteBuf result = ctx.alloc().buffer();
                byte[] encryptedKeys = CryptoService.encryptCipherKeys(keysDataJoined, remotePublicKey, randomService.getKeyGenerator());
                burn(keysDataJoined);
                result.writeBytes(encryptedKeys);

                if (log.isDebugEnabled()) {
                    log.debug("sent encrypted keysData {}\n {}", encryptedKeys.length, prettyDump(encryptedKeys));
                }

                return Futures.immediateFuture(result);

            }
        }, executorService);
    }

    private void burn(byte[] buffer) {
        Arrays.fill(buffer, (byte)0);
    }
    
    public SessionData getClientSession() {
        return clientSession;
    }

}
