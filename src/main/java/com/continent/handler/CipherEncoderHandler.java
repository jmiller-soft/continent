package com.continent.handler;

import com.continent.random.RandomDelegator;
import com.continent.service.CryptoService;
import com.continent.service.Protocol;
import io.netty.buffer.*;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.MessageToByteEncoder;
import io.netty.handler.codec.socksx.SocksVersion;
import io.netty.handler.codec.socksx.v5.Socks5AddressDecoder;
import io.netty.handler.codec.socksx.v5.Socks5AddressType;
import io.netty.handler.codec.socksx.v5.Socks5CommandType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class CipherEncoderHandler extends MessageToByteEncoder<ByteBuf> {

    public static final ByteBuf RANDOM_PACKET_HEADER = Unpooled.copyLong(1L);
    
    final Logger log = LoggerFactory.getLogger(CipherEncoderHandler.class);
    
    private final Logger clientHostsLog = LoggerFactory.getLogger("client-hosts-log");
    
    private boolean firstPacket = true;
    private final RandomDelegator randomGenerator;
    private final CryptoService holder;
    private final byte[] sessionId;
    
    public CipherEncoderHandler(RandomDelegator randomGenerator, byte[] sessionId, CryptoService holder) {
        super();
        this.randomGenerator = randomGenerator;
        this.sessionId = sessionId;
        this.holder = holder;
    }
    
    protected String prettyDump(byte[] seedBytes) {
        return ByteBufUtil.prettyHexDump(Unpooled.wrappedBuffer(seedBytes));
    }


    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (clientHostsLog.isDebugEnabled() && ((ByteBuf) msg).readableBytes() > 5) {
            ByteBuf in = ((ByteBuf) msg);
            in.markReaderIndex();
            final byte version = in.readByte();
            if (version == SocksVersion.SOCKS5.byteValue()) {
                final Socks5CommandType type = Socks5CommandType.valueOf(in.readByte());
                in.skipBytes(1); // RSV
                final Socks5AddressType dstAddrType = Socks5AddressType.valueOf(in.readByte());
                final String dstAddr = Socks5AddressDecoder.DEFAULT.decodeAddress(dstAddrType, in);
                final int dstPort = in.readUnsignedShort();
                
                clientHostsLog.debug("connection: {}, host: {}:{}", ctx.channel().remoteAddress(), dstAddr, dstPort);
            }
            in.resetReaderIndex();
        }

        try {
            super.write(ctx, msg, promise);
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }
    
    @Override
    protected void encode(ChannelHandlerContext ctx, ByteBuf input, ByteBuf output) throws Exception {
        ByteBuf buf = ctx.alloc().buffer();
        int randomLength = 0;
        int dataLength = 0;
        if (firstPacket) {
            firstPacket = false;

            output.writeBytes(sessionId);

            dataLength = encodeFirstHeader(buf);
        } else {
            dataLength = Protocol.DATA_LENGTH_SIZE + Protocol.RANDOM_DATA_LENGTH_SIZE;
        }

        dataLength += input.readableBytes();
        
        if ((input instanceof CompositeByteBuf) 
                && ((CompositeByteBuf)input).numComponents() == 2
                    && ((CompositeByteBuf)input).component(0).equals(RANDOM_PACKET_HEADER)) {
            randomLength = calcRandomDataLength(ctx.channel(), input);
            input = Unpooled.EMPTY_BUFFER;
        } else {
            randomLength = calcRandomDataLength(ctx.channel(), dataLength);
        }
        
        buf.writeInt(input.readableBytes());
        buf.writeInt(randomLength);

        ByteBufOutputStream bf = new ByteBufOutputStream(output);
        holder.encrypt(bf, new ByteBufInputStream(buf));
        buf.release();
        holder.encrypt(bf, new ByteBufInputStream(input));
        
        addRandomTail(output, randomLength);
    }

    protected abstract int encodeFirstHeader(ByteBuf buf);
    
    protected void addRandomTail(ByteBuf output, int randomLength) {
        if (randomLength > 0) {
            for (int i = 0; i < randomLength; ) {
                for (int rnd = randomGenerator.nextInt(),
                        n = Math.min(randomLength - i, Integer.SIZE/Byte.SIZE);
                        n-- > 0; rnd >>= Byte.SIZE) {
                    output.writeByte((byte)rnd);
                    i++;
                }
            }
        }
    }

    protected int calcRandomDataLength(Channel channel, ByteBuf input) {
        return ((CompositeByteBuf)input).component(1).readInt();
    }
    
    protected int calcRandomDataLength(Channel channel, int dataLength) {
//        if (dataLength < 1500) {
//            int low = Math.max(0, 1000-dataLength);
//            int high = Math.max(0, 1500-dataLength);
//            return ThreadLocalRandom.current().nextInt(low, high);
//        }
//        return 0;
        return randomGenerator.nextInt(1500);
    }
    
}
