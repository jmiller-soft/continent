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

import java.util.Arrays;

import net.sf.ntru.exception.NtruException;

/**
 * A polynomial class that combines two coefficients into one <code>long</code> value for
 * faster multiplication in 64 bit environments.<br/>
 * Coefficients can be between 0 and 2047 and are stored in pairs in the bits 0..10 and 24..34 of a <code>long</code> number.
 */
class LongPolynomial2 {
    private long[] coeffs;   // each representing two coefficients in the original IntegerPolynomial
    private int numCoeffs;
    
    /**
     * Constructs a <code>LongPolynomial2</code> from a <code>IntegerPolynomial</code>. The two polynomials are independent of each other.
     * @param p the original polynomial. Coefficients must be between 0 and 2047.
     */
    LongPolynomial2(IntegerPolynomial p) {
        numCoeffs = p.coeffs.length;
        coeffs = new long[(numCoeffs+1) / 2];
        int idx = 0;
        for (int pIdx=0; pIdx<numCoeffs;) {
            int c0 = p.coeffs[pIdx++];
            while (c0 < 0)
                c0 += 2048;
            long c1 = pIdx<numCoeffs ? p.coeffs[pIdx++] : 0;
            while (c1 < 0)
                c1 += 2048;
            coeffs[idx] = c0 + (c1<<24);
            idx++;
        }
    }
    
    private LongPolynomial2(long[] coeffs) {
        this.coeffs = coeffs;
    }
    
    private LongPolynomial2(int N) {
        coeffs = new long[N];
    }
    
    /** Multiplies the polynomial with another, taking the indices mod N and the values mod 2048. */
    public LongPolynomial2 mult(LongPolynomial2 poly2) {
        int N = coeffs.length;
        if (poly2.coeffs.length!=N || numCoeffs!=poly2.numCoeffs)
            throw new NtruException("Number of coefficients must be the same");

        LongPolynomial2 c = multRecursive(poly2);
        
        if (c.coeffs.length > N) {
            if (numCoeffs%2 == 0) {
                for (int k=N; k<c.coeffs.length; k++)
                    c.coeffs[k-N] = (c.coeffs[k-N]+c.coeffs[k]) & 0x7FF0007FFL;
                c.coeffs = Arrays.copyOf(c.coeffs, N);
            }
            else {
                for (int k=N; k<c.coeffs.length; k++) {
                    c.coeffs[k-N] = c.coeffs[k-N] + (c.coeffs[k-1]>>24);
                    c.coeffs[k-N] = c.coeffs[k-N] + ((c.coeffs[k]&2047)<<24);
                    c.coeffs[k-N] &= 0x7FF0007FFL;
                }
                c.coeffs = Arrays.copyOf(c.coeffs, N);
                c.coeffs[c.coeffs.length-1] &= 2047;
            }
        }

        c = new LongPolynomial2(c.coeffs);
        c.numCoeffs = numCoeffs;
        return c;
    }
    
    public IntegerPolynomial toIntegerPolynomial() {
        int[] intCoeffs = new int[numCoeffs];
        int uIdx = 0;
        for (int i=0; i<coeffs.length; i++) {
            intCoeffs[uIdx++] = (int)(coeffs[i] & 2047);
            if (uIdx < numCoeffs)
                intCoeffs[uIdx++] = (int)((coeffs[i]>>24) & 2047);
        }
        return new IntegerPolynomial(intCoeffs);
    }

    /** Karatsuba multiplication */
    private LongPolynomial2 multRecursive(LongPolynomial2 poly2) {
        long[] a = coeffs;
        long[] b = poly2.coeffs;

        int n = poly2.coeffs.length;
        if (n <= 32) {
            int cn = 2 * n;
            LongPolynomial2 c = new LongPolynomial2(new long[cn]);
            for (int k=0; k<cn; k++) {
                for (int i=Math.max(0, k-n+1); i<=Math.min(k,n-1); i++) {
                    long c0 = a[k-i] * b[i];
                    long cu = c0&0x7FF000000L + (c0&2047);
                    long co = (c0>>>48) & 2047;
                    
                    c.coeffs[k] = (c.coeffs[k]+cu) & 0x7FF0007FFL;
                    c.coeffs[k+1] = (c.coeffs[k+1]+co) & 0x7FF0007FFL;
                }
            }
            return c;
        }
        else {
            int n1 = n / 2;

            LongPolynomial2 a1 = new LongPolynomial2(Arrays.copyOf(a, n1));
            LongPolynomial2 a2 = new LongPolynomial2(Arrays.copyOfRange(a, n1, n));
            LongPolynomial2 b1 = new LongPolynomial2(Arrays.copyOf(b, n1));
            LongPolynomial2 b2 = new LongPolynomial2(Arrays.copyOfRange(b, n1, n));

            LongPolynomial2 A = a1.clone();
            A.add(a2);
            LongPolynomial2 B = b1.clone();
            B.add(b2);

            LongPolynomial2 c1 = a1.multRecursive(b1);
            LongPolynomial2 c2 = a2.multRecursive(b2);
            LongPolynomial2 c3 = A.multRecursive(B);
            c3.sub(c1);
            c3.sub(c2);

            LongPolynomial2 c = new LongPolynomial2(2*n);
            for (int i=0; i<c1.coeffs.length; i++)
                c.coeffs[i] = c1.coeffs[i] & 0x7FF0007FFL;
            for (int i=0; i<c3.coeffs.length; i++)
                c.coeffs[n1+i] = (c.coeffs[n1+i] + c3.coeffs[i]) & 0x7FF0007FFL;
            for (int i=0; i<c2.coeffs.length; i++)
                c.coeffs[2*n1+i] = (c.coeffs[2*n1+i] + c2.coeffs[i]) & 0x7FF0007FFL;
            return c;
        }
    }

    /**
     * Adds another polynomial which can have a different number of coefficients.
     * @param b another polynomial
     */
    private void add(LongPolynomial2 b) {
        if (b.coeffs.length > coeffs.length)
            coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] = (coeffs[i] + b.coeffs[i]) & 0x7FF0007FFL;
    }
    
    /**
     * Subtracts another polynomial which can have a different number of coefficients.
     * @param b another polynomial
     */
    private void sub(LongPolynomial2 b) {
        if (b.coeffs.length > coeffs.length)
            coeffs = Arrays.copyOf(coeffs, b.coeffs.length);
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] = (0x0800000800000L + coeffs[i] - b.coeffs[i]) & 0x7FF0007FFL;
    }

    /**
     * Subtracts another polynomial which must have the same number of coefficients,
     * and applies an AND mask to the upper and lower halves of each coefficients.
     * @param b another polynomial
     * @param mask a bit mask less than 2048 to apply to each 11-bit coefficient
     */
    void subAnd(LongPolynomial2 b, int mask) {
        long longMask = (((long)mask)<<24) + mask;
        for (int i=0; i<b.coeffs.length; i++)
            coeffs[i] = (0x0800000800000L + coeffs[i] - b.coeffs[i]) & longMask;
    }

    /**
     * Multiplies this polynomial by 2 and applies an AND mask to the upper and 
     * lower halves of each coefficients.
     * @param mask a bit mask less than 2048 to apply to each 11-bit coefficient
     */
    void mult2And(int mask) {
        long longMask = (((long)mask)<<24) + mask;
        for (int i=0; i<coeffs.length; i++)
            coeffs[i] = (coeffs[i]<<1) & longMask;
    }

    @Override
    public LongPolynomial2 clone() {
        LongPolynomial2 p = new LongPolynomial2(coeffs.clone());
        p.numCoeffs = numCoeffs;
        return p;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof LongPolynomial2)
            return Arrays.equals(coeffs, ((LongPolynomial2)obj).coeffs);
        else
            return false;
    }
}