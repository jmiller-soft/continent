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

package net.sf.ntru.encrypt;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;

/**
 * A set of parameters for NtruEncrypt. Several predefined parameter sets are available and new ones can be created as well.
 */
public class EncryptionParameters implements Cloneable {
    /** A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for key size. */
    public static final EncryptionParameters EES1087EP2 = new EncryptionParameters(1087, 2048, 120, 120, 0, 256, 13, 25, 14, true, new byte[] {0, 6, 3}, true, false, "SHA-512");
    
    /** A product-form version of <code>EES1087EP2</code> */
    public static final EncryptionParameters EES1087EP2_FAST = new EncryptionParameters(1087, 2048, 8, 8, 11, 120, 0, 256, 13, 25, 14, true, new byte[] {0, 6, 3}, true, true, "SHA-512");
    
    /** A conservative (in terms of security) parameter set that gives 256 bits of security and is a tradeoff between key size and encryption/decryption speed. */
    public static final EncryptionParameters EES1171EP1 = new EncryptionParameters(1171, 2048, 106, 106, 0, 256, 13, 20, 15, true, new byte[] {0, 6, 4}, true, false, "SHA-512");
    
    /** A product-form version of <code>EES1171EP1</code> */
    public static final EncryptionParameters EES1171EP1_FAST = new EncryptionParameters(1171, 2048, 8, 7, 11, 106, 0, 256, 13, 20, 15, true, new byte[] {0, 6, 4}, true, true, "SHA-512");
    
    /** A conservative (in terms of security) parameter set that gives 256 bits of security and is optimized for encryption/decryption speed. */
    public static final EncryptionParameters EES1499EP1 = new EncryptionParameters(1499, 2048, 79, 79, 0, 256, 13, 17, 19, true, new byte[] {0, 6, 5}, true, false, "SHA-512");
    
    /** A product-form version of <code>EES1499EP1</code> */
    public static final EncryptionParameters EES1499EP1_FAST = new EncryptionParameters(1499, 2048, 7, 6, 11, 79, 0, 256, 13, 17, 19, true, new byte[] {0, 6, 5}, true, true, "SHA-512");
    
    /** A parameter set that gives 128 bits of security and uses simple ternary polynomials. */
    public static final EncryptionParameters APR2011_439 = new EncryptionParameters(439, 2048, 146, 130, 126, 128, 12, 32, 9, true, new byte[] {0, 7, 101}, true, false, "SHA-256");
    
    /** Like <code>APR2011_439</code>, this parameter set gives 128 bits of security but uses product-form polynomials and <code>f=1+pF</code>. */
    public static final EncryptionParameters APR2011_439_FAST = new EncryptionParameters(439, 2048, 9, 8, 5, 130, 126, 128, 12, 32, 9, true, new byte[] {0, 7, 101}, true, true, "SHA-256");
    
    /** A parameter set that gives 256 bits of security and uses simple ternary polynomials. */
    public static final EncryptionParameters APR2011_743 = new EncryptionParameters(743, 2048, 248, 220, 60, 256, 12, 27, 14, true, new byte[] {0, 7, 105}, false, false, "SHA-512");
    
    /** Like <code>APR2011_743</code>, this parameter set gives 256 bits of security but uses product-form polynomials and <code>f=1+pF</code>. */
    public static final EncryptionParameters APR2011_743_FAST = new EncryptionParameters(743, 2048, 11, 11, 15, 220, 60, 256, 12, 27, 14, true, new byte[] {0, 7, 105}, false, true, "SHA-512");
    
    public enum TernaryPolynomialType {SIMPLE, PRODUCT};
    
    public int N, q, df, df1, df2, df3;
    int dr, dr1, dr2, dr3, dg, llen, maxMsgLenBytes, db, bufferLenBits, bufferLenTrits, dm0, maxM1, pkLen, c, minCallsR, minCallsMask;
    boolean hashSeed;
    byte[] oid;
    boolean sparse;
    boolean fastFp;
    TernaryPolynomialType polyType;
    public String hashAlg;
    
    /**
     * Constructs a parameter set that uses ternary private keys (i.e. </code>polyType=SIMPLE</code>).
     * @param N            number of polynomial coefficients
     * @param q            modulus
     * @param df           number of ones in the private polynomial <code>f</code>
     * @param dm0          minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param maxM1        maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. Values greater than zero cause the constant coefficient of the message to always be zero.
     * @param db           number of random bits to prepend to the message; should be a multiple of 8
     * @param c            a parameter for the Index Generation Function ({@link IndexGenerator})
     * @param minCallsR    minimum number of hash calls for the IGF to make
     * @param minCallsMask minimum number of calls to generate the masking polynomial
     * @param hashSeed     whether to hash the seed in the MGF first (true) or use the seed directly (false)
     * @param oid          three bytes that uniquely identify the parameter set
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
     * @param fastFp       whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is ternary (false)
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
     */
    public EncryptionParameters(int N, int q, int df, int dm0, int maxM1, int db, int c, int minCallsR, int minCallsMask, boolean hashSeed, byte[] oid, boolean sparse, boolean fastFp, String hashAlg) {
        this.N = N;
        this.q = q;
        this.df = df;
        this.db = db;
        this.dm0 = dm0;
        this.maxM1 = maxM1;
        this.c = c;
        this.minCallsR = minCallsR;
        this.minCallsMask = minCallsMask;
        this.hashSeed = hashSeed;
        this.oid = oid;
        this.sparse = sparse;
        this.fastFp = fastFp;
        this.polyType = TernaryPolynomialType.SIMPLE;
        this.hashAlg = hashAlg;
        init();
    }

    /**
     * Constructs a parameter set that uses product-form private keys (i.e. </code>polyType=PRODUCT</code>).
     * @param N number of polynomial coefficients
     * @param q modulus
     * @param df1          number of ones in the private polynomial <code>f1</code>
     * @param df2          number of ones in the private polynomial <code>f2</code>
     * @param df3          number of ones in the private polynomial <code>f3</code>
     * @param dm0          minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param maxM1        maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. Values greater than zero cause the constant coefficient of the message to always be zero.
     * @param db           number of random bits to prepend to the message; should be a multiple of 8
     * @param c            a parameter for the Index Generation Function ({@link IndexGenerator})
     * @param minCallsR    minimum number of hash calls for the IGF to make
     * @param minCallsMask minimum number of calls to generate the masking polynomial
     * @param hashSeed     whether to hash the seed in the MGF first (true) or use the seed directly (false)
     * @param oid          three bytes that uniquely identify the parameter set
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
     * @param fastFp       whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is ternary (false)
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>
     */
    public EncryptionParameters(int N, int q, int df1, int df2, int df3, int dm0, int maxM1, int db, int c, int minCallsR, int minCallsMask, boolean hashSeed, byte[] oid, boolean sparse, boolean fastFp, String hashAlg) {
        this.N = N;
        this.q = q;
        this.df1 = df1;
        this.df2 = df2;
        this.df3 = df3;
        this.db = db;
        this.dm0 = dm0;
        this.maxM1 = maxM1;
        this.c = c;
        this.minCallsR = minCallsR;
        this.minCallsMask = minCallsMask;
        this.hashSeed = hashSeed;
        this.oid = oid;
        this.sparse = sparse;
        this.fastFp = fastFp;
        this.polyType = TernaryPolynomialType.PRODUCT;
        this.hashAlg = hashAlg;
        init();
    }

    private void init() {
        dr = df;
        dr1 = df1;
        dr2 = df2;
        dr3 = df3;
        dg = N / 3;
        llen = 1;   // ceil(log2(maxMsgLenBytes))
        if (maxM1 > 0)
            maxMsgLenBytes = (N-1)*3/2/8 - llen - db/8;   // only N-1 coeffs b/c the constant coeff is not used
        else
            maxMsgLenBytes = N*3/2/8 - llen - db/8;
        bufferLenBits = (N*3/2+7)/8*8 + 1;
        bufferLenTrits = N - 1;
        pkLen = db;
    }

    /**
     * Reads a parameter set from an input stream.
     * @param is an input stream
     * @throws IOException
     */
    public EncryptionParameters(InputStream is) throws IOException {
        DataInputStream dis = new DataInputStream(is);
        N = dis.readInt();
        q = dis.readInt();
        df = dis.readInt();
        df1 = dis.readInt();
        df2 = dis.readInt();
        df3 = dis.readInt();
        db = dis.readInt();
        dm0 = dis.readInt();
        maxM1 = dis.readInt();
        c = dis.readInt();
        minCallsR = dis.readInt();
        minCallsMask = dis.readInt();
        hashSeed = dis.readBoolean();
        oid = new byte[3];
        dis.read(oid);
        sparse = dis.readBoolean();
        fastFp = dis.readBoolean();
        polyType = TernaryPolynomialType.values()[dis.read()];
        hashAlg = dis.readUTF();
        init();
    }

    public EncryptionParameters clone() {
        if (polyType == TernaryPolynomialType.SIMPLE)
            return new EncryptionParameters(N, q, df, dm0, maxM1, db, c, minCallsR, minCallsMask, hashSeed, oid, sparse, fastFp, hashAlg);
        else
            return new EncryptionParameters(N, q, df1, df2, df3, dm0, maxM1, db, c, minCallsR, minCallsMask, hashSeed, oid, sparse, fastFp, hashAlg);
    }
    
    /**
     * Returns the maximum length a plaintext message can be with this parameter set.
     * @return the maximum length in bytes
     */
    public int getMaxMessageLength() {
        return maxMsgLenBytes;
    }
    
    /**
     * Returns the length of a message after encryption with this parameter set.<br/>
     * The length does not depend on the input size.
     * @return the length in bytes
     */
    public int getOutputLength() {
        int logq = 32 - Integer.numberOfLeadingZeros(q - 1);   // ceil(log q)
        return (N*logq+7) / 8;
    }
    
    /**
     * Writes the parameter set to an output stream
     * @param os an output stream
     * @throws IOException
     */
    public void writeTo(OutputStream os) throws IOException {
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeInt(N);
        dos.writeInt(q);
        dos.writeInt(df);
        dos.writeInt(df1);
        dos.writeInt(df2);
        dos.writeInt(df3);
        dos.writeInt(db);
        dos.writeInt(dm0);
        dos.writeInt(maxM1);
        dos.writeInt(c);
        dos.writeInt(minCallsR);
        dos.writeInt(minCallsMask);
        dos.writeBoolean(hashSeed);
        dos.write(oid);
        dos.writeBoolean(sparse);
        dos.writeBoolean(fastFp);
        dos.write(polyType.ordinal());
        dos.writeUTF(hashAlg);
        dos.flush();
    }

    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + N;
        result = prime * result + bufferLenBits;
        result = prime * result + bufferLenTrits;
        result = prime * result + c;
        result = prime * result + db;
        result = prime * result + df;
        result = prime * result + df1;
        result = prime * result + df2;
        result = prime * result + df3;
        result = prime * result + dg;
        result = prime * result + dm0;
        result = prime * result + maxM1;
        result = prime * result + dr;
        result = prime * result + dr1;
        result = prime * result + dr2;
        result = prime * result + dr3;
        result = prime * result + (fastFp ? 1231 : 1237);
        result = prime * result + ((hashAlg == null) ? 0 : hashAlg.hashCode());
        result = prime * result + (hashSeed ? 1231 : 1237);
        result = prime * result + llen;
        result = prime * result + maxMsgLenBytes;
        result = prime * result + minCallsMask;
        result = prime * result + minCallsR;
        result = prime * result + Arrays.hashCode(oid);
        result = prime * result + pkLen;
        result = prime * result + ((polyType == null) ? 0 : polyType.hashCode());
        result = prime * result + q;
        result = prime * result + (sparse ? 1231 : 1237);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        EncryptionParameters other = (EncryptionParameters) obj;
        if (N != other.N)
            return false;
        if (bufferLenBits != other.bufferLenBits)
            return false;
        if (bufferLenTrits != other.bufferLenTrits)
            return false;
        if (c != other.c)
            return false;
        if (db != other.db)
            return false;
        if (df != other.df)
            return false;
        if (df1 != other.df1)
            return false;
        if (df2 != other.df2)
            return false;
        if (df3 != other.df3)
            return false;
        if (dg != other.dg)
            return false;
        if (dm0 != other.dm0)
            return false;
        if (maxM1 != other.maxM1)
            return false;
        if (dr != other.dr)
            return false;
        if (dr1 != other.dr1)
            return false;
        if (dr2 != other.dr2)
            return false;
        if (dr3 != other.dr3)
            return false;
        if (fastFp != other.fastFp)
            return false;
        if (hashAlg == null) {
            if (other.hashAlg != null)
                return false;
        } else if (!hashAlg.equals(other.hashAlg))
            return false;
        if (hashSeed != other.hashSeed)
            return false;
        if (llen != other.llen)
            return false;
        if (maxMsgLenBytes != other.maxMsgLenBytes)
            return false;
        if (minCallsMask != other.minCallsMask)
            return false;
        if (minCallsR != other.minCallsR)
            return false;
        if (!Arrays.equals(oid, other.oid))
            return false;
        if (pkLen != other.pkLen)
            return false;
        if (polyType == null) {
            if (other.polyType != null)
                return false;
        } else if (!polyType.equals(other.polyType))
            return false;
        if (q != other.q)
            return false;
        if (sparse != other.sparse)
            return false;
        return true;
    }

    @Override
    public String toString() {
        StringBuilder output = new StringBuilder("EncryptionParameters(N=" + N +" q=" + q);
        if (polyType == TernaryPolynomialType.SIMPLE)
            output.append(" polyType=SIMPLE df=" + df);
        else
            output.append(" polyType=PRODUCT df1=" + df1 + " df2=" + df2 + " df3=" + df3);
        output.append(" dm0=" + dm0 + " M=" + maxM1 + " db=" + db + " c=" + c + " minCallsR=" + minCallsR + " minCallsMask=" + minCallsMask +
                " hashSeed=" + hashSeed + " hashAlg=" + hashAlg + " oid=" + Arrays.toString(oid) + " sparse=" + sparse + ")");
        return output.toString();
    }
}