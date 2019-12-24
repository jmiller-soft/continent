/**
 * Copyright (c) 2011, Tim Buktu
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package net.sf.ntru.polynomial;

import static java.math.BigInteger.ONE;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import net.sf.ntru.arith.BigIntEuclidean;
import net.sf.ntru.arith.IntEuclidean;
import net.sf.ntru.exception.NtruException;
import net.sf.ntru.sign.SignatureParameters;
import net.sf.ntru.util.ArrayEncoder;
import net.sf.ntru.util.PlatformUtil;

/**
 * A polynomial with <code>int</code> coefficients.<br/>
 * Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
 * not but return the result as a new polynomial.
 */
public class IntegerPolynomial implements Polynomial {
    private static final int NUM_EQUAL_RESULTANTS = 3;
    /**
     * Prime numbers &gt; 4500 for resultant computation. Starting them below ~4400 causes incorrect results occasionally.
     * Fortunately, 4500 is about the optimum number for performance.<br/>
     * This array contains enough prime numbers so primes never have to be computed on-line for any standard {@link SignatureParameters}.
     */
    private static final int[] PRIMES = new int[] {
        4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583,
        4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
        4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,
        4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,
        4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937,
        4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003,
        5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,
        5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179,
        5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279,
        5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
        5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,
        5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521,
        5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639,
        5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693,
        5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,
        5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,
        5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939,
        5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053,
        6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
        6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221,
        6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301,
        6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
        6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473,
        6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571,
        6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673,
        6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761,
        6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
        6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,
        6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997,
        7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103,
        7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
        7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297,
        7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411,
        7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
        7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
        7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643,
        7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723,
        7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829,
        7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,
        7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017,
        8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111,
        8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219,
        8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291,
        8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387,
        8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501,
        8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597,
        8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677,
        8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741,
        8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831,
        8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929,
        8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011,
        9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109,
        9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199,
        9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283,
        9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377,
        9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439,
        9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533,
        9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631,
        9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733,
        9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811,
        9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887,
        9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973};
    private static final List<BigInteger> BIGINT_PRIMES;

    static {
        BIGINT_PRIMES = new ArrayList<BigInteger>();
        for (int p: PRIMES)
            BIGINT_PRIMES.add(BigInteger.valueOf(p));
    }
    
    public int[] coeffs;
    
    /**
     * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
     * @param N the number of coefficients
     */
    public IntegerPolynomial(int N) {
        coeffs = new int[N];
    }
    
    /**
     * Constructs a new polynomial with a given set of coefficients.
     * @param coeffs the coefficients
     */
    public IntegerPolynomial(int[] coeffs) {
        this.coeffs = coeffs;
    }
    
    /**
     * Constructs a <code>IntegerPolynomial</code> from a <code>BigIntPolynomial</code>. The two polynomials are independent of each other.
     * @param p the original polynomial
     */
    public IntegerPolynomial(BigIntPolynomial p) {
        coeffs = new int[p.coeffs.length];
        for (int i=0; i<p.coeffs.length; i++)
            coeffs[i] = p.coeffs[i].intValue();
    }
    
    /**
     * Decodes a byte array to a polynomial with <code>N</code> ternary coefficients<br/>
     * Ignores any excess bytes.
     * @param data an encoded ternary polynomial
     * @param N number of coefficients
     * @param skipFirst whether to leave the constant coefficient zero and start populating at the linear coefficient
     * @return the decoded polynomial
     */
    public static IntegerPolynomial fromBinary3Sves(byte[] data, int N, boolean skipFirst) {
        return new IntegerPolynomial(ArrayEncoder.decodeMod3Sves(data, N, skipFirst));
    }
    
    /**
     * Converts a byte array produced by {@link #toBinary3Tight()} to a polynomial.
     * @param b a byte array
     * @param N number of coefficients
     * @return the decoded polynomial
     */
    public static IntegerPolynomial fromBinary3Tight(byte[] b, int N) {
        return new IntegerPolynomial(ArrayEncoder.decodeMod3Tight(b, N));
    }
    
    /**
     * Reads data produced by {@link #toBinary3Tight()} from an input stream and converts it to a polynomial.
     * @param is an input stream
     * @param N number of coefficients
     * @return the decoded polynomial
     */
    public static IntegerPolynomial fromBinary3Tight(InputStream is, int N) throws IOException {
        return new IntegerPolynomial(ArrayEncoder.decodeMod3Tight(is, N));
    }
    
    /**
     * Returns a polynomial with N coefficients between <code>0</code> and <code>q-1</code>.<br/>
     * <code>q</code> must be a power of 2.<br/>
     * Ignores any excess bytes.
     * @param data an encoded ternary polynomial
     * @param N number of coefficients
     * @param q
     * @return the decoded polynomial
     */
    public static IntegerPolynomial fromBinary(byte[] data, int N, int q) {
        return new IntegerPolynomial(ArrayEncoder.decodeModQ(data, N, q));
    }
    
    /**
     * Returns a polynomial with N coefficients between <code>0</code> and <code>q-1</code>.<br/>
     * <code>q</code> must be a power of 2.<br/>
     * Ignores any excess bytes.
     * @param is an encoded ternary polynomial
     * @param N number of coefficients
     * @param q
     * @return the decoded polynomial
     */
    public static IntegerPolynomial fromBinary(InputStream is, int N, int q) throws IOException {
        return new IntegerPolynomial(ArrayEncoder.decodeModQ(is, N, q));
    }
    
    /**
     * Encodes a polynomial with ternary coefficients to binary.
     * <code>coeffs[2*i]</code> and <code>coeffs[2*i+1]</code> must not both equal -1 for any integer </code>i<code>,
     * so this method is only safe to use with polynomials produced by <code>fromBinary3Sves()</code>.
     * @param skipFirst whether to skip the constant coefficient
     * @return the encoded polynomial
     */
    public byte[] toBinary3Sves(boolean skipFirst) {
        return ArrayEncoder.encodeMod3Sves(coeffs, skipFirst);
    }
    
    /**
     * Converts a polynomial with ternary coefficients to binary.
     * @return the encoded polynomial
     */
    public byte[] toBinary3Tight() {
        return ArrayEncoder.encodeMod3Tight(coeffs);
    }
    
    /**
     * Encodes a polynomial whose coefficients are between 0 and q, to binary. q must be a power of 2.
     * @param q
     * @return the encoded polynomial
     */
    public byte[] toBinary(int q) {
        return ArrayEncoder.encodeModQ(coeffs, q);
    }
    
    /**
     * Like {@link #toBinary(int)} but only returns the first <code>numBytes</code> bytes of the encoding.
     * @param q
     * @return the encoded polynomial
     */
    public byte[] toBinaryTrunc(int q, int numBytes) {
        return ArrayEncoder.encodeModQTrunc(coeffs, q, numBytes);
    }
    
    /**
     * Optimized version of {@link #toBinary(int)} for <code>q=4</code>.<br/>
     * Encodes the low 2 bits of all coefficients in a byte array.
     * @return a byte array equal to what <code>toBinary(4)</code> would return
     */
    public byte[] toBinary4() {
        byte[] data = new byte[(coeffs.length+3)/4];
        int i = 0;
        while (i < coeffs.length-3) {
            int c0 = coeffs[i] & 3;
            int c1 = coeffs[i+1] & 3;
            int c2 = coeffs[i+2] & 3;
            int c3 = coeffs[i+3] & 3;
            int d = c0 + (c1<<2) + (c2<<4) + (c3<<6);
            data[i/4] = (byte)d;
            i += 4;
        }
        
        // handle the last 0 to 3 coefficients
        if (i >= coeffs.length)
            return data;
        int last = data.length - 1;
        data[last] = (byte)(coeffs[i] & 3);
        i++;
        
        if (i >= coeffs.length)
            return data;
        data[last] |= (byte)((coeffs[i]&3) << 2);
        i++;
        
        if (i >= coeffs.length)
            return data;
        data[last] |= (byte)((coeffs[i]&3) << 4);
        i++;
        
        if (i >= coeffs.length)
            return data;
        data[last] |= (byte)((coeffs[i]&3) << 6);
        
        return data;
    }
    
    /** Multiplies the polynomial with another, taking the values mod modulus and the indices mod N */
    public IntegerPolynomial mult(IntegerPolynomial poly2, int modulus) {
        IntegerPolynomial c = mult(poly2);
        c.mod(modulus);
        return c;
    }
    
    /** Multiplies the polynomial with another, taking the indices mod N */
    public IntegerPolynomial mult(IntegerPolynomial poly2) {
        int N = coeffs.length;
        if (poly2.coeffs.length != N)
            throw new NtruException("Number of coefficients must be the same");
        
        IntegerPolynomial c = multRecursive(poly2);
        
        if (c.coeffs.length > N) {
            for (int k=N; k<c.coeffs.length; k++)
                c.coeffs[k-N] += c.coeffs[k];
            c.coeffs = Arrays.copyOf(c.coeffs, N);
        }
        return c;
    }
    
    @Override
    public BigIntPolynomial mult(BigIntPolynomial poly2) {
        return new BigIntPolynomial(this).multSmall(poly2);
    }
    
    /** Karatsuba multiplication */
    private IntegerPolynomial multRecursive(IntegerPolynomial poly2) {
        int[] a = coeffs;
        int[] b = poly2.coeffs;
        
        int n = poly2.coeffs.length;
        if (n <= 32) {
            int cn = 2 * n - 1;
            IntegerPolynomial c = new IntegerPolynomial(new int[cn]);
            for (int k=0; k<cn; k++)
                for (int i=Math.max(0, k-n+1); i<=Math.min(k,n-1); i++)
                    c.coeffs[k] += b[i] * a[k-i];
            return c;
        }
        else {
            int n1 = n / 2;
            
            IntegerPolynomial a1 = new IntegerPolynomial(Arrays.copyOf(a, n1));
            IntegerPolynomial a2 = new IntegerPolynomial(Arrays.copyOfRange(a, n1, n));
            IntegerPolynomial b1 = new IntegerPolynomial(Arrays.copyOf(b, n1));
            IntegerPolynomial b2 = new IntegerPolynomial(Arrays.copyOfRange(b, n1, n));
            
            // make a copy of a1 that is the same length as a2
            IntegerPolynomial A = new IntegerPolynomial(Arrays.copyOf(a1.coeffs, a2.coeffs.length));
            A.add(a2);
            // make a copy of b1 that is the same length as b2
            IntegerPolynomial B = new IntegerPolynomial(Arrays.copyOf(b1.coeffs, b2.coeffs.length));
            B.add(b2);
            
            IntegerPolynomial c1 = a1.multRecursive(b1);
            IntegerPolynomial c2 = a2.multRecursive(b2);
            IntegerPolynomial c3 = A.multRecursive(B);
            c3.sub(c1);
            c3.sub(c2);
            
            IntegerPolynomial c = new IntegerPolynomial(2*n-1);
            for (int i=0; i<c1.coeffs.length; i++)
                c.coeffs[i] = c1.coeffs[i];
            for (int i=0; i<c3.coeffs.length; i++)
                c.coeffs[n1+i] += c3.coeffs[i];
            for (int i=0; i<c2.coeffs.length; i++)
                c.coeffs[2*n1+i] += c2.coeffs[i];
            return c;
        }
    }
    
    /**
     * Tests if this polynomial is invertible modulo 2.
     * If a polynomial is invertible modulo 2, it is invertible modulo any power of 2.
     * @return <code>true</code> if an inverse mod 2<sup>k</sup> for all k exists, <code>false</code> otherwise
     */
    public boolean isInvertiblePow2() {
        return invertF2() != null;
    }
    
    /**
     * Computes the inverse mod <code>q; q</code> must be a power of 2.<br/>
     * Returns <code>null</code> if the polynomial is not invertible.<br/>
     * The algorithm is described in <a href="http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf">
     * Almost Inverses and Fast NTRU Key Generation</a>.
     * @param q the modulus
     * @return a new polynomial, or <code>null</code> if no inverse exists
     */
    public IntegerPolynomial invertFq(int q) {
        IntegerPolynomial Fq = invertF2();
        if (Fq == null)
            return null;
        return mod2ToModq(Fq, q);
    }
    
    /**
     * Computes the inverse mod 2.
     * Returns <code>null</code> if the polynomial is not invertible.<br/>
     * The algorithm is described in <a href="http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf">
     * Almost Inverses and Fast NTRU Key Generation</a>.
     * @return a new polynomial, or <code>null</code> if no inverse exists
     */
    private IntegerPolynomial invertF2() {
        int N = coeffs.length;
        int k = 0;
        IntegerPolynomial b = new IntegerPolynomial(N+1);
        b.coeffs[0] = 1;
        IntegerPolynomial c = new IntegerPolynomial(N+1);
        IntegerPolynomial f = new IntegerPolynomial(Arrays.copyOf(coeffs, N+1));
        f.mod2();
        // set g(x) = x^N − 1
        IntegerPolynomial g = new IntegerPolynomial(N+1);
        g.coeffs[0] = 1;
        g.coeffs[N] = 1;
        while (true) {
            while (f.coeffs[0] == 0) {
                for (int i=1; i<=N; i++) {
                    f.coeffs[i-1] = f.coeffs[i];   // f(x) = f(x) / x
                    c.coeffs[N+1-i] = c.coeffs[N-i];   // c(x) = c(x) * x
                }
                f.coeffs[N] = 0;
                c.coeffs[0] = 0;
                k++;
                if (f.equalsZero())
                    return null;   // not invertible
            }
            if (f.equalsOne())
                break;
            if (f.degree() < g.degree()) {
                // exchange f and g
                IntegerPolynomial temp = f;
                f = g;
                g = temp;
                // exchange b and c
                temp = b;
                b = c;
                c = temp;
            }
            f.add(g);
            f.mod2();
            b.add(c);
            b.mod2();
        }
        
        if (b.coeffs[N] != 0)
            return null;
        // Fq(x) = x^(N-k) * b(x)
        IntegerPolynomial Fq = new IntegerPolynomial(N);
        int j = 0;
        k %= N;
        for (int i=N-1; i>=0; i--) {
            j = i - k;
            if (j < 0)
                j += N;
            Fq.coeffs[j] = b.coeffs[i];
        }
        
        return Fq;
    }
    
    /**
     * Computes the inverse mod <code>q</code> from the inverse mod 2.<br/>
     * The algorithm is described in <a href="http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf">
     * Almost Inverses and Fast NTRU Key Generation</a>.
     * @param Fq
     * @param q
     * @return The inverse of this polynomial mod q
     */
    private IntegerPolynomial mod2ToModq(IntegerPolynomial Fq, int q) {
        if (PlatformUtil.is64BitJVM() && q==2048) {
            LongPolynomial2 thisLong = new LongPolynomial2(this);
            LongPolynomial2 FqLong = new LongPolynomial2(Fq);
            int v = 2;
            while (v < q) {
                v *= 2;
                LongPolynomial2 temp = FqLong.clone();
                temp.mult2And(v-1);
                FqLong = thisLong.mult(FqLong).mult(FqLong);
                temp.subAnd(FqLong, v-1);
                FqLong = temp;
            }
            return FqLong.toIntegerPolynomial();
        }
        else {
            int v = 2;
            while (v < q) {
                v *= 2;
                IntegerPolynomial temp = Fq.clone();
                temp.mult2(v);
                Fq = mult(Fq, v).mult(Fq, v);
                temp.sub(Fq, v);
                Fq = temp;
            }
            return Fq;
        }
    }
    
    /**
     * Computes the inverse mod 3.
     * Returns <code>null</code> if the polynomial is not invertible.<br/>
     * The algorithm is described in <a href="http://www.securityinnovation.com/uploads/Crypto/NTRUTech014.pdf">
     * Almost Inverses and Fast NTRU Key Generation</a>.
     * @return a new polynomial, or <code>null</code> if no inverse exists
     */
    public IntegerPolynomial invertF3() {
        int N = coeffs.length;
        int k = 0;
        IntegerPolynomial b = new IntegerPolynomial(N+1);
        b.coeffs[0] = 1;
        IntegerPolynomial c = new IntegerPolynomial(N+1);
        IntegerPolynomial f = new IntegerPolynomial(N+1);
        f.coeffs = Arrays.copyOf(coeffs, N+1);
        f.modPositive(3);
        // set g(x) = x^N − 1
        IntegerPolynomial g = new IntegerPolynomial(N+1);
        g.coeffs[0] = -1;
        g.coeffs[N] = 1;
        while (true) {
            while (f.coeffs[0] == 0) {
                for (int i=1; i<=N; i++) {
                    f.coeffs[i-1] = f.coeffs[i];   // f(x) = f(x) / x
                    c.coeffs[N+1-i] = c.coeffs[N-i];   // c(x) = c(x) * x
                }
                f.coeffs[N] = 0;
                c.coeffs[0] = 0;
                k++;
                if (f.equalsZero())
                    return null;   // not invertible
            }
            if (f.equalsAbsOne())
                break;
            if (f.degree() < g.degree()) {
                // exchange f and g
                IntegerPolynomial temp = f;
                f = g;
                g = temp;
                // exchange b and c
                temp = b;
                b = c;
                c = temp;
            }
            if (f.coeffs[0] == g.coeffs[0]) {
                f.sub(g, 3);
                b.sub(c, 3);
            }
            else {
                f.add(g, 3);
                b.add(c, 3);
            }
        }
        
        if (b.coeffs[N] != 0)
            return null;
        // Fp(x) = [+-] x^(N-k) * b(x)
        IntegerPolynomial Fp = new IntegerPolynomial(N);
        int j = 0;
        k %= N;
        for (int i=N-1; i>=0; i--) {
            j = i - k;
            if (j < 0)
                j += N;
            Fp.coeffs[j] = f.coeffs[0] * b.coeffs[i];
        }
        
        Fp.ensurePositive(3);
        return Fp;
    }
    
    /**
     * Resultant of this polynomial with <code>x^n-1</code> using a probabilistic algorithm.
     * <p/>
     * Unlike EESS, this implementation does not compute all resultants modulo primes
     * such that their product exceeds the maximum possible resultant, but rather stops
     * when <code>NUM_EQUAL_RESULTANTS</code> consecutive modular resultants are equal.<br/>
     * This means the return value may be incorrect. Experiments show this happens in
     * about 1 out of 100 cases when <code>N=439</code> and <code>NUM_EQUAL_RESULTANTS=2</code>,
     * so the likelyhood of leaving the loop too early is <code>(1/100)^(NUM_EQUAL_RESULTANTS-1)</code>.
     * <p/>
     * Because of the above, callers must verify the output and try a different polynomial if necessary.
     * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1)</code> for some integer <code>t</code>.
     */
    public Resultant resultant() {
        int N = coeffs.length;
        
        // Compute resultants modulo prime numbers. Continue until NUM_EQUAL_RESULTANTS consecutive modular resultants are equal.
        LinkedList<ModularResultant> modResultants = new LinkedList<ModularResultant>();
        BigInteger prime = null;
        BigInteger pProd = ONE;
        BigInteger pProd2 = null;
        BigInteger pProd2n = null;
        BigInteger res = ONE;
        int numEqual = 1;   // number of consecutive modular resultants equal to each other
        Iterator<BigInteger> primes = BIGINT_PRIMES.iterator();
        while (true) {
            prime = primes.hasNext() ? primes.next() : prime.nextProbablePrime();
            ModularResultant crr = resultant(prime.intValue());
            modResultants.add(crr);
            
            BigInteger temp = pProd.multiply(prime);
            BigIntEuclidean er = BigIntEuclidean.calculate(prime, pProd);
            BigInteger resPrev = res;
            res = res.multiply(er.x.multiply(prime));
            BigInteger res2 = crr.res.multiply(er.y.multiply(pProd));
            res = res.add(res2).mod(temp);
            pProd = temp;
            
            pProd2 = pProd.shiftRight(1);
            pProd2n = pProd2.negate();
            if (res.compareTo(pProd2) > 0)
                res = res.subtract(pProd);
            else if (res.compareTo(pProd2n) < 0)
                res = res.add(pProd);
            
            if (res.equals(resPrev)) {
                numEqual++;
                if (numEqual >= NUM_EQUAL_RESULTANTS)
                    break;
            }
            else
                numEqual = 1;
        }
        
        // Combine modular rho's to obtain the final rho.
        // For efficiency, first combine all pairs of small resultants to bigger resultants,
        // then combine pairs of those, etc. until only one is left.
        while (modResultants.size() > 1) {
            ModularResultant modRes1 = modResultants.removeFirst();
            ModularResultant modRes2 = modResultants.removeFirst();
            ModularResultant modRes3 = ModularResultant.combineRho(modRes1, modRes2);
            modResultants.addLast(modRes3);
        }
        BigIntPolynomial rhoP = modResultants.getFirst().rho;
        
        if (res.compareTo(pProd2) > 0)
            res = res.subtract(pProd);
        if (res.compareTo(pProd2n) < 0)
            res = res.add(pProd);
        
        for (int i=0; i<N; i++) {
            BigInteger c = rhoP.coeffs[i];
            if (c.compareTo(pProd2) > 0)
                rhoP.coeffs[i] = c.subtract(pProd);
            if (c.compareTo(pProd2n) < 0)
                rhoP.coeffs[i] = c.add(pProd);
        }

        return new Resultant(rhoP, res);
    }
    
    /**
     * Resultant of this polynomial with <code>x^n-1 mod p</code>.<br/>
     * @return <code>(rho, res)</code> satisfying <code>res = rho*this + t*(x^n-1) mod p</code> for some integer <code>t</code>.
     */
    public ModularResultant resultant(int p) {
        // Add a coefficient as the following operations involve polynomials of degree deg(f)+1
        int[] fcoeffs = Arrays.copyOf(coeffs, coeffs.length+1);
        IntegerPolynomial f = new IntegerPolynomial(fcoeffs);
        int N = fcoeffs.length;
        
        IntegerPolynomial a = new IntegerPolynomial(N);
        a.coeffs[0] = -1;
        a.coeffs[N-1] = 1;
        IntegerPolynomial b = new IntegerPolynomial(f.coeffs);
        IntegerPolynomial v1 = new IntegerPolynomial(N);
        IntegerPolynomial v2 = new IntegerPolynomial(N);
        v2.coeffs[0] = 1;
        int da = N - 1;
        int db = b.degree();
        int ta = da;
        int c = 0;
        int r = 1;
        while (db > 0) {
            c = invert(b.coeffs[db], p);
            c = (c * a.coeffs[da]) % p;
            a.multShiftSub(b, c, da-db, p);
            v1.multShiftSub(v2, c, da-db, p);
            
            da = a.degree();
            if (da < db) {
                r *= pow(b.coeffs[db], ta-da, p);
                r %= p;
                if (ta%2==1 && db%2==1)
                    r = (-r) % p;
                IntegerPolynomial temp = a;
                a = b;
                b = temp;
                int tempdeg = da;
                da = db;
                temp = v1;
                v1 = v2;
                v2 = temp;
                ta = db;
                db = tempdeg;
            }
        }
        r *= pow(b.coeffs[0], da, p);
        r %= p;
        c = invert(b.coeffs[0], p);
        v2.mult(c);
        v2.mod(p);
        v2.mult(r);
        v2.mod(p);
        
        // drop the highest coefficient so #coeffs matches the original input
        v2.coeffs = Arrays.copyOf(v2.coeffs, v2.coeffs.length-1);
        return new ModularResultant(new BigIntPolynomial(v2), BigInteger.valueOf(r), BigInteger.valueOf(p));
    }
    
    /** Calculates the inverse of n mod modulus */
    private int invert(int n, int modulus) {
        n %= modulus;
        if (n < 0)
            n += modulus;
        return IntEuclidean.calculate(n, modulus).x;
    }
    
    /** Calculates a^b mod modulus */
    private int pow(int a, int b, int modulus) {
        int p = 1;
        for (int i=0; i<b; i++)
            p = (p*a) % modulus;
        return p;
    }
    
    /**
     * Computes <code>this-b*c*(x^k) mod p</code> and stores the result in this polynomial.<br/>
     * See steps 4a,4b in EESS algorithm 2.2.7.1.
     * @param b
     * @param c
     * @param k
     * @param p
     */
    private void multShiftSub(IntegerPolynomial b, int c, int k, int p) {
        int N = coeffs.length;
        for (int i=k; i<N; i++)
            coeffs[i] = (coeffs[i]-b.coeffs[i-k]*c) % p;
    }
    
    /**
     * Returns the degree of the polynomial
     * @return the degree
     */
    private int degree() {
        int degree = coeffs.length - 1;
        while (degree>0 && coeffs[degree]==0)
            degree--;
        return degree;
    }
    
    /**
     * Adds another polynomial which must not have more coefficients than <code>this</code>
     * polynomial, and takes the coefficient values mod <code>modulus</code>.
     * @param b another polynomial
     */
    public void add(IntegerPolynomial b, int modulus) {
        add(b);
        mod(modulus);
    }
    
    /**
     * Adds another <code>IntegerPolynomial</code> which must not have more coefficients
     * than <code>this</code> polynomial.
     * @param b another polynomial
     */
    public void add(IntegerPolynomial b) {
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] += b.coeffs[i];
    }
    
    /**
     * Adds a <code>TernaryPolynomial</code> which must not have more coefficients
     * than <code>this</code> polynomial.
     * @param b another polynomial
     */
    public void add(TernaryPolynomial b) {
        for (int i: b.getOnes())
            coeffs[i]++;
        for (int i: b.getNegOnes())
            coeffs[i]--;
    }
    
    /**
     * Subtracts another polynomial which can have a different number of coefficients,
     * and takes the coefficient values mod <code>modulus</code>.
     * @param b another polynomial
     */
    private void sub(IntegerPolynomial b, int modulus) {
        sub(b);
        mod(modulus);
    }
    
    /**
     * Subtracts another polynomial which must not have more coefficients than <code>this</code>
     * polynomial.
     * @param b another polynomial
     */
    public void sub(IntegerPolynomial b) {
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] -= b.coeffs[i];
    }
    
    /**
     * Subtracts a <code>int</code> from each coefficient. Does not return a new polynomial but modifies this polynomial.
     * @param b a number to subtract from each coefficient
     */
    private void sub(int b) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] -= b;
    }
    
    /**
     * Multiplies each coefficient by a <code>int</code>. Does not return a new polynomial but modifies this polynomial.
     * @param factor
     */
    public void mult(int factor) {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] *= factor;
    }
    
    /**
     * Multiplies each coefficient by 2 and applies a modulus. Does not return a new polynomial but modifies this polynomial.
     * @param modulus a modulus
     */
    private void mult2(int modulus) {
        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] *= 2;
            coeffs[i] %= modulus;
        }
    }
    
    /**
     * Multiplies each coefficient by 3 and applies a modulus. Does not return a new polynomial but modifies this polynomial.
     * @param modulus a modulus
     */
    public void mult3(int modulus) {
        if (modulus == 2048)
          for (int i=0; i<coeffs.length; i++)
              coeffs[i] = (coeffs[i]*3) & 2047;

        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] *= 3;
            coeffs[i] %= modulus;
        }
    }
    
    /**
     * Divides each coefficient by <code>k</code> and rounds to the nearest integer.
     * Does not return a new polynomial but modifies this polynomial.
     * @param k the divisor
     */
    public void div(int k) {
        int ka = k / 2;
        if (k == 2048)
            for (int i=0; i<coeffs.length; i++)
                coeffs[i] = (coeffs[i]+ka) >> 11;
        else {
            int kb = (1-k) / 2;
            for (int i=0; i<coeffs.length; i++) {
                coeffs[i] += coeffs[i]>0 ? ka : kb;
                coeffs[i] /= k;
            }
        }
    }
    
    /**
     * Optimized version of <code>modPositive(2)</code>.
     */
    private void mod2() {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] &= 1;
    }
    
    /**
     * Takes each coefficient modulo 3 such that all coefficients are ternary.
     */
    public void mod3() {
        for (int i=0; i<coeffs.length; i++) {
            coeffs[i] %= 3;
            if (coeffs[i] > 1)
                coeffs[i] -= 3;
            if (coeffs[i] < -1)
                coeffs[i] += 3;
        }
    }
    
    /**
     * Ensures all coefficients are between 0 and <code>modulus-1</code>
     * @param modulus a modulus
     */
    public void modPositive(int modulus) {
        if (modulus == 2048)
            for (int i=0; i<coeffs.length; i++)
                coeffs[i] &= 2047;
        else {
            mod(modulus);
            ensurePositive(modulus);
        }
    }
    
    /** Reduces all coefficients to the interval [-modulus/2, modulus/2) */
    public void modCenter(int modulus) {
        if (modulus == 2048)
            for (int i=0; i<coeffs.length; i++) {
                int c = coeffs[i] & 2047;
                if (c >= 1024)
                    c -= 2048;
                coeffs[i] = c;
            }
        else {
            mod(modulus);
            for (int j=0;j<coeffs.length;j++){
                while (coeffs[j] < modulus/2)
                    coeffs[j] += modulus;
                while (coeffs[j] >= modulus/2)
                    coeffs[j]-=modulus;
            }
        }
    }
    
    /**
     * Takes each coefficient modulo <code>modulus</code>.
     */
    void mod(int modulus) {
        if (modulus == 2048)
            for (int i=0; i<coeffs.length; i++)
                coeffs[i] &= 2047;
        else
            for (int i=0; i<coeffs.length; i++)
                coeffs[i] %= modulus;
    }
    
    /**
     * Ensures all coefficients are between 0 and 3
     */
    public void modPositive4() {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] &= 3;
    }
    
    /**
     * Adds <code>modulus</code> until all coefficients are above 0.
     * @param modulus a modulus
     */
    public void ensurePositive(int modulus) {
        if (modulus == 2048)
            for (int i=0; i<coeffs.length; i++)
                coeffs[i] &= 2047;
        else
            for (int i=0; i<coeffs.length; i++)
                while (coeffs[i] < 0)
                    coeffs[i] += modulus;
    }
    
    /**
     * Computes the centered euclidean norm of the polynomial.
     * @param q a modulus
     * @return the centered norm
     */
    public long centeredNormSq(int q) {
        int N = coeffs.length;
        IntegerPolynomial p = clone();
        p.shiftGap(q);
        
        long sum = 0;
        long sqSum = 0;
        for (int c: p.coeffs) {
            sum += c;
            sqSum += c * c;
        }
        
        long centeredNormSq = sqSum - sum*sum/N;
        return centeredNormSq;
    }
    
    /**
     * Shifts all coefficients so the largest gap is centered around <code>-q/2</code>.
     * @param q a modulus
     */
    private void shiftGap(int q) {
        modCenter(q);
        
        int[] sorted = coeffs.clone();
        Arrays.sort(sorted);
        int maxrange = 0;
        int maxrangeStart = 0;
        for (int i=0; i<sorted.length-1; i++) {
            int range = sorted[i+1] - sorted[i];
            if (range > maxrange) {
                maxrange = range;
                maxrangeStart = sorted[i];
            }
        }
        
        int pmin = sorted[0];
        int pmax = sorted[sorted.length-1];
        
        int j = q - pmax + pmin;
        int shift;
        if (j > maxrange)
            shift = (pmax+pmin) / 2;
        else
            shift = maxrangeStart + maxrange/2 + q/2;
        
        sub(shift);
    }
    
    /**
     * Shifts the values of all coefficients to the interval <code>[-q/2, q/2]</code>.
     * @param q a modulus
     */
    public void center0(int q) {
        if (q == 2048)
            for (int i=0; i<coeffs.length; i++) {
                int c = coeffs[i] & 2047;
                if (c >= 1024)
                    c -= 2048;
                coeffs[i] = c;
            }
        else
            for (int i=0; i<coeffs.length; i++) {
                while (coeffs[i] < -q/2)
                    coeffs[i] += q;
                while (coeffs[i] > q/2)
                    coeffs[i] -= q;
            }
    }
    
    /**
     * Returns the sum of all coefficients, i.e. evaluates the polynomial at 1.
     * @return the sum of all coefficients
     */
    public int sumCoeffs() {
        int sum = 0;
        for (int i=0; i<coeffs.length; i++)
            sum += coeffs[i];
        return sum;
    }
    
    /**
     * Tests if <code>p(x) = 0</code>.
     * @return true iff all coefficients are zeros
     */
    private boolean equalsZero() {
        for (int i=0; i<coeffs.length; i++)
            if (coeffs[i] != 0)
                return false;
        return true;
    }
    
    /**
     * Tests if <code>p(x) = 1</code>.
     * @return true iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1
     */
    boolean equalsOne() {
        for (int i=1; i<coeffs.length; i++)
            if (coeffs[i] != 0)
                return false;
        return coeffs[0] == 1;
    }
    
    /**
     * Tests if <code>|p(x)| = 1</code>.
     * @return true iff all coefficients are equal to zero, except for the lowest coefficient which must equal 1 or -1
     */
    private boolean equalsAbsOne() {
        for (int i=1; i<coeffs.length; i++)
            if (coeffs[i] != 0)
                return false;
        return Math.abs(coeffs[0]) == 1;
    }
    
    /**
     * Counts the number of coefficients equal to an integer
     * @param value an integer
     * @return the number of coefficients equal to <code>value</code>
     */
    public int count(int value) {
        int count = 0;
        for (int coeff: coeffs)
            if (coeff == value)
                count++;
        return count;
    }
    
    public boolean isTernary() {
        for (int c: coeffs)
            if (c<-1 || c>1)
                return false;
        return true;
    }
    
    /**
     * Tests whether all coefficients are between 0 and <code>modulus</code>
     * @param modulus the modulus
     * @return <code>true</code> if <code>0 &le; c &lt; modulus</code> for all coefficients
     *         <code>c</code>, <code>false</code> otherwise
     */
    public boolean isReduced(int modulus) {
        for (int c: coeffs)
            if (c<0 || c>=modulus)
                return false;
        return true;
    }
    
    /**
     * Multiplication by <code>X</code> in <code>Z[X]/Z[X^n-1]</code>.
     */
    public void rotate1() {
        int clast = coeffs[coeffs.length-1];
        for (int i=coeffs.length-1; i>0; i--)
            coeffs[i] = coeffs[i-1];
        coeffs[0] = clast;
    }
    
   public void clear() {
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = 0;
    }

    @Override
    public IntegerPolynomial toIntegerPolynomial() {
        return clone();
    }
   
    @Override
    public IntegerPolynomial clone() {
        return new IntegerPolynomial(coeffs.clone());
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(coeffs);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof IntegerPolynomial)
            return Arrays.equals(coeffs, ((IntegerPolynomial)obj).coeffs);
        else
            return false;
    }
}