package com.continent.engine.rc6;

import java.math.BigInteger;
import java.math.BigDecimal;
import java.util.Arrays;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * An RC6 engine.
 */
public class RC6_NEngine
    implements BlockCipher
{
//    private static final int wordSize = 256;
    private final int wordSize;
//    private static final int wordSize = 64;
    private final int bytesPerWord;

    /*
     * the number of rounds to perform
     */
    private final int _noRounds;

    /*
     * the expanded key array of size 2*(rounds + 1)
     */
    private BigInteger _S[];

    /*
     * our "magic constants" for wordSize 32
     *
     * Pw = Odd((e-2) * 2^wordsize)
     * Qw = Odd((o-2) * 2^wordsize)
     *
     * where e is the base of natural logarithms (2.718281828...)
     * and o is the golden ratio (1.61803398...)
     */
//    private static final BigInteger P64 = new BigInteger("b7e151628aed2a6b", 16);
//    private static final BigInteger Q64 = new BigInteger("9e3779b97f4a7c15", 16);
//    private static final BigInteger LGW = BigInteger.valueOf(6);        // log2(64)
//    private final BigInteger P64 = new BigInteger("b7e151628aed2a6abf7158809cf4f3c7", 16);
//    private final BigInteger Q64 = new BigInteger("9e3779b97f4a7c15f39cc0605cedc834", 16);
//    private final BigInteger LGW = BigInteger.valueOf(7);          // log2(128)
//    private static final BigInteger P64 = new BigInteger("b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef", 16);
//    private static final BigInteger Q64 = new BigInteger("9e3779b97f4a7c15f39cc0605cedc8341082276bf3a27251f86c6a11d0c18e95", 16);
//    private static final BigInteger LGW = BigInteger.valueOf(8);          // log2(256)
//    private static final BigInteger P64 = new BigInteger("b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef324e7738926cfbe5f4bf8d8d8c31d763da06c80abb1185eb4f7c7b5757f59584", 16);
//    private static final BigInteger Q64 = new BigInteger("9e3779b97f4a7c15f39cc0605cedc8341082276bf3a27251f86c6a11d0c18e952767f0b153d27b7f0347045b5bf1827f01886f0928403002c1d64ba40f335e36", 16);
//    private static final BigInteger LGW = BigInteger.valueOf(9);          // log2(512)
    
    private final BigInteger P64;
    private final BigInteger Q64;
    private final BigInteger LGW;

    private boolean forEncryption;

    public RC6_NEngine(int rounds, int wordSize, BigInteger p, BigInteger q, BigInteger lgw)
    {
        _noRounds = rounds;
        this.wordSize = wordSize;
        bytesPerWord = wordSize / 8;
        this.P64 = p;
        this.Q64 = q;
        this.LGW = lgw;
    }


    public String getAlgorithmName()
    {
        return "RC6";
    }

    public int getBlockSize()
    {
        return 4 * bytesPerWord;
    }

    /**
     * initialise a RC5-32 cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    public void init(
        boolean             forEncryption,
        CipherParameters    params)
    {
        if (!(params instanceof KeyParameter))
        {
            throw new IllegalArgumentException("invalid parameter passed to RC6 init - " + params.getClass().getName());
        }

        KeyParameter       p = (KeyParameter)params;
        this.forEncryption = forEncryption;
        setKey(p.getKey());
    }

    public int processBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        int blockSize = getBlockSize();
        if (_S == null)
        {
            throw new IllegalStateException("RC6 engine not initialised");
        }
        if ((inOff + blockSize) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }
        if ((outOff + blockSize) > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        return (forEncryption)
            ?   encryptBlock(in, inOff, out, outOff) 
            :   decryptBlock(in, inOff, out, outOff);
    }

    public static void main(String[] args) {
        BigDecimal bd =  new BigDecimal("2.71828182845904523536028747135266249775724709369995957496696762772407663035354759457138217852516642742746639193200305992181741359662904357290033429526059563073813232");
        bd = bd.add(BigDecimal.valueOf(-2));
        
        BigDecimal bd2 = new BigDecimal("2");
        bd2 = bd2.pow(512);
        System.out.println("bd2 " + bd2);
        bd = bd.multiply(bd2);
        System.out.println("P = " + bd.toBigInteger().toString(16));

        BigDecimal phi = new BigDecimal("1.61803398874989484820458683436563811772030917980576286213544862270526046281890244970720720418939113748475408807538689175212663386222353693179318006076672635443338908");
        phi = phi.add(BigDecimal.valueOf(-1));

        phi = phi.multiply(bd2);
        System.out.println("Q = " + phi.toBigInteger().toString(16));
    }
    
    public void reset()
    {
    }

    /**
     * Re-key the cipher.
     * <p>
     * @param  key  the key to be used
     */
    private void setKey(
        byte[]      key)
    {

        //
        // KEY EXPANSION:
        //
        // There are 3 phases to the key expansion.
        //
        // Phase 1:
        //   Copy the secret key K[0...b-1] into an array L[0..c-1] of
        //   c = ceil(b/u), where u = wordSize/8 in little-endian order.
        //   In other words, we fill up L using u consecutive key bytes
        //   of K. Any unfilled byte positions in L are zeroed. In the
        //   case that b = c = 0, set c = 1 and L[0] = 0.
        //
        // compute number of dwords
        BigInteger[]   L = new BigInteger[(key.length + bytesPerWord - 1) / bytesPerWord];

        // load all key bytes into array of key dwords
        for (int i = 0; i != key.length; i++)
        {
            BigInteger b = shiftLeft(BigInteger.valueOf((long)(key[i] & 0xff)), (8 * (i % bytesPerWord)));
            BigInteger val = L[i / bytesPerWord];
            if (val == null) {
                val = BigInteger.ZERO;
            }
            L[i / bytesPerWord] = add(val, b);
        }

        //
        // Phase 2:
        //   Key schedule is placed in a array of 2+2*ROUNDS+2 = 44 dwords.
        //   Initialize S to a particular fixed pseudo-random bit pattern
        //   using an arithmetic progression modulo 2^wordsize determined
        //   by the magic numbers, Pw & Qw.
        //
        _S            = new BigInteger[2+2*_noRounds+2];

        _S[0] = P64;
        for (int i=1; i < _S.length; i++)
        {
            _S[i] = add(_S[i-1], Q64);
        }

        //
        // Phase 3:
        //   Mix in the user's secret key in 3 passes over the arrays S & L.
        //   The max of the arrays sizes is used as the loop control
        //
        int iter;

        if (L.length > _S.length)
        {
            iter = 3 * L.length;
        }
        else
        {
            iter = 3 * _S.length;
        }

        BigInteger A = BigInteger.ZERO;
        BigInteger B = BigInteger.ZERO;
        int i = 0, j = 0;

        for (int k = 0; k < iter; k++)
        {
            A = _S[i] = rotateLeft(add(add(_S[i], A), B), BigInteger.valueOf(3));
            B =  L[j] = rotateLeft(add(add(L[j], A), B), add(A, B));
            i = (i+1) % _S.length;
            j = (j+1) %  L.length;
        }
    }

    private int encryptBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        // load A,B,C and D registers from in.
        BigInteger A = bytesToWord(in, inOff);
        BigInteger B = bytesToWord(in, inOff + bytesPerWord);
        BigInteger C = bytesToWord(in, inOff + bytesPerWord*2);
        BigInteger D = bytesToWord(in, inOff + bytesPerWord*3);
        
        // Do pseudo-round #0: pre-whitening of B and D
        B = add(B, _S[0]);
        D = add(D, _S[1]);

        // perform round #1,#2 ... #ROUNDS of encryption 
        for (int i = 1; i <= _noRounds; i++)
        {
            BigInteger t = BigInteger.ZERO,u = BigInteger.ZERO;
            
            t = multiply(B, add(multiply(B, BigInteger.valueOf(2)), BigInteger.ONE));
            t = rotateLeft(t, LGW);
            
            u = multiply(D, add(multiply(D, BigInteger.valueOf(2)), BigInteger.ONE));
            u = rotateLeft(u, LGW);
            
            A = A.xor(t);
            A = rotateLeft(A,u);
            A = add(A, _S[2*i]);
            
            C = C.xor(u);
            C = rotateLeft(C,t);
            C = add(C, _S[2*i+1]);
            
            BigInteger temp = A;
            A = B;
            B = C;
            C = D;
            D = temp;            
        }
        // do pseudo-round #(ROUNDS+1) : post-whitening of A and C
        A = add(A, _S[2*_noRounds+2]);
        C = add(C, _S[2*_noRounds+3]);
            
        // store A, B, C and D registers to out        
        wordToBytes(A, out, outOff);
        wordToBytes(B, out, outOff + bytesPerWord);
        wordToBytes(C, out, outOff + bytesPerWord*2);
        wordToBytes(D, out, outOff + bytesPerWord*3);
        
        return 4 * bytesPerWord;
    }

    private int decryptBlock(
        byte[]  in,
        int     inOff,
        byte[]  out,
        int     outOff)
    {
        // load A,B,C and D registers from out.
        BigInteger A = bytesToWord(in, inOff);
        BigInteger B = bytesToWord(in, inOff + bytesPerWord);
        BigInteger C = bytesToWord(in, inOff + bytesPerWord*2);
        BigInteger D = bytesToWord(in, inOff + bytesPerWord*3);

        // Undo pseudo-round #(ROUNDS+1) : post whitening of A and C 
        C = subtract(C, _S[2*_noRounds+3]);
        A = subtract(A, _S[2*_noRounds+2]);
        
        // Undo round #ROUNDS, .., #2,#1 of encryption 
        for (int i = _noRounds; i >= 1; i--)
        {
            BigInteger t= BigInteger.ZERO,u = BigInteger.ZERO;
            
            BigInteger temp = D;
            D = C;
            C = B;
            B = A;
            A = temp;
            
            t = multiply(B, add(multiply(B, BigInteger.valueOf(2)), BigInteger.ONE));
            t = rotateLeft(t, LGW);
            
            u = multiply(D, add(multiply(D, BigInteger.valueOf(2)), BigInteger.ONE));
            u = rotateLeft(u, LGW);
            
            C = subtract(C, _S[2*i+1]);
            C = rotateRight(C,t);
            C = C.xor(u);
            
            A = subtract(A, _S[2*i]);
            A = rotateRight(A,u);
            A = A.xor(t);
            
        }
        // Undo pseudo-round #0: pre-whitening of B and D
        D = subtract(D, _S[1]);
        B = subtract(B, _S[0]);
        
        wordToBytes(A, out, outOff);
        wordToBytes(B, out, outOff + bytesPerWord);
        wordToBytes(C, out, outOff + bytesPerWord*2);
        wordToBytes(D, out, outOff + bytesPerWord*3);
        
        return 4 * bytesPerWord;
    }

    
    //////////////////////////////////////////////////////////////
    //
    // PRIVATE Helper Methods
    //
    //////////////////////////////////////////////////////////////

    /**
     * Perform a left "spin" of the word. The rotation of the given
     * word <em>x</em> is rotated left by <em>y</em> bits.
     * Only the <em>lg(wordSize)</em> low-order bits of <em>y</em>
     * are used to determine the rotation amount. Here it is 
     * assumed that the wordsize used is 32.
     * <p>
     * @param  x  word to rotate
     * @param  y    number of bits to rotate % wordSize
     */
    private BigInteger rotateLeft(BigInteger x, BigInteger y)
    {
        int a = y.intValue() & (wordSize-1);
        int b = wordSize - (y.intValue() & (wordSize-1));
        
        return shiftLeft(x, a).or(shiftRight(x, b));
    }

    public BigInteger shiftRight(BigInteger l, int shiftBy) {
        BigInteger res = l.shiftRight(shiftBy);
        res = normalize(res);
        return res;
    }
    
    public BigInteger multiply(BigInteger a, BigInteger b) {
        BigInteger res = a.multiply(b);
        res = normalize(res);
        return res;
    }

    public BigInteger add(BigInteger a, BigInteger b) {
        BigInteger res = a.add(b);
        res = normalize(res);
        return res;
    }
    
    public BigInteger subtract(BigInteger a, BigInteger b) {
        BigInteger res = a.subtract(b);
        res = normalize(res);
        return res;
    }

    public BigInteger shiftLeft(BigInteger l, int shiftBy) {
        BigInteger res = l.shiftLeft(shiftBy);
        res = normalize(res);
        return res;
    }

    protected BigInteger normalize(BigInteger res) {
        byte[] array = res.toByteArray();
        if (array.length < bytesPerWord) {
            return res;
        }

        if (array.length > bytesPerWord) {
            // BigInteger strips leading zeros
            Arrays.fill(array, 0, array.length - bytesPerWord, (byte)0);
        }
//        array = Arrays.copyOfRange(array, array.length - bytesPerWord, array.length);
//        System.out.println(res);
        return new BigInteger(1, array);
    }

    
    /**
     * Perform a right "spin" of the word. The rotation of the given
     * word <em>x</em> is rotated left by <em>y</em> bits.
     * Only the <em>lg(wordSize)</em> low-order bits of <em>y</em>
     * are used to determine the rotation amount. Here it is 
     * assumed that the wordsize used is a power of 2.
     * <p>
     * @param  x  word to rotate
     * @param  y    number of bits to rotate % wordSize
     */
    private BigInteger rotateRight(BigInteger x, BigInteger y)
    {
        int a = y.intValue() & (wordSize-1);
        int b = wordSize - (y.intValue() & (wordSize-1));
        
        return shiftRight(x, a).or(shiftLeft(x, b));
    }
    
    private BigInteger bytesToWord(
        byte[]  src,
        int     srcOff)
    {
        BigInteger    word = BigInteger.ZERO;

        for (int i = bytesPerWord - 1; i >= 0; i--)
        {
            word = add(shiftLeft(word, 8), BigInteger.valueOf((long)(src[i + srcOff] & 0xff)));
        }

        return word;
    }

    private void wordToBytes(
            BigInteger    word,
        byte[]  dst,
        int     dstOff)
    {
        for (int i = 0; i < bytesPerWord; i++)
        {
            dst[i + dstOff] = word.byteValue();
            word = shiftRight(word, 8);
        }
    }
}
