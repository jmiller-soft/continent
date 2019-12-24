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

package net.sf.ntru.arith;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * An implementation of the
 * <a href="http://en.wikipedia.org/wiki/Sch%C3%B6nhage%E2%80%93Strassen_algorithm">Schönhage-Strassen algorithm</a>
 * for multiplying large numbers.
 * <p/>
 * References:
 * <ol>
 *   <li><a href="http://www.scribd.com/doc/68857222/Schnelle-Multiplikation-gro%C3%9Fer-Zahlen">
 *       Arnold Schönhage und Volker Strassen: Schnelle Multiplikation großer Zahlen, Computing 7, 1971, Springer-Verlag, S. 281–292</a></li>
 *   <li><a href="http://malte-leip.net/beschreibung_ssa.pdf">Eine verständliche Beschreibung des Schönhage-Strassen-Algorithmus</a></li>
 * </ol>
 * <p/>
 * Numbers are internally represented as <code>int</code> arrays; the <code>int</code>s are interpreted as unsigned numbers.
 */
public class SchönhageStrassen {
    private static final int KARATSUBA_THRESHOLD = 32;   // min #ints for Karatsuba
    
    /**
     * Multiplies two {@link BigInteger}s using the Schönhage-Strassen algorithm.<br/>
     * <a href="http://en.wikipedia.org/wiki/Karatsuba_algorithm">Karatsuba</a> is used instead of
     * Schönhage-Strassen if the numbers are in a range where Karatsuba is more efficient.
     * @param a
     * @param b
     * @return a <code>BigInteger</code> equal to <code>a.multiply(b)</code>
     */
    public static BigInteger mult(BigInteger a, BigInteger b) {
        // remove any minus signs, multiply, then fix sign
        int signum = a.signum() * b.signum();
        if (a.signum() < 0)
            a = a.negate();
        if (b.signum() < 0)
            b = b.negate();
        
        int[] aIntArr = toIntArray(a);
        int[] bIntArr = toIntArray(b);
        
        int[] cIntArr = mult(aIntArr, a.bitLength(), bIntArr, b.bitLength());
        
        BigInteger c = toBigInteger(cIntArr);
        if (signum < 0)
            c = c.negate();
        
        return c;
    }
    
    /**
     * Multiplies two <b>positive</b> numbers represented as int arrays, i.e. in base <code>2^32</code>.
     * Positive means an int is always interpreted as an unsigned number, regardless of the sign bit.<br/>
     * The arrays must be ordered least significant to most significant,
     * so the least significant digit must be at index 0.</br>
     * Schönhage-Strassen is used unless the numbers are in a range where
     * <a href="http://en.wikipedia.org/wiki/Karatsuba_algorithm">Karatsuba</a> is more efficient.
     * @param a
     * @param b
     * @return a*b
     */
    public static int[] mult(int[] a, int[] b) {
        return mult(a, a.length*32, b, b.length*32);
    }
    
    /**
     * This is the core method. It multiplies two <b>positive</b> numbers of length <code>aBitLen</code>
     * and </code>bBitLen</code> that are represented as int arrays, i.e. in base 2^32.
     * Positive means an int is always interpreted as an unsigned number, regardless of the sign bit.<br/>
     * The arrays must be ordered least significant to most significant, so the least significant digit
     * must be at index 0.</br>
     * Schönhage-Strassen is used unless the numbers are in a range where
     * <a href="http://en.wikipedia.org/wiki/Karatsuba_algorithm">Karatsuba</a> is more efficient.
     * <p/>
     * The Schönhage-Strassen algorithm works as follows:
     * <ol>
     *   <li>Given numbers a and b, split both numbers into pieces of length 2^(n-1) bits.</li>
     *   <li>Take the low n+2 bits of each piece of a, zero-pad them to 3n+5 bits,
     *       and concatenate them to a new number u.</li>
     *   <li>Do the same for b to obtain v.</li>
     *   <li>Calculate all pieces of z' by multiplying u and v (using Schönhage-Strassen or another
     *       algorithm). The product will contain all pieces of a*b mod n+2.</li>
     *   <li>Pad the pieces of a and b from step 1 to 2^(n+1) bits.</li>
     *   <li>Perform a
     *       <a href="http://en.wikipedia.org/wiki/Discrete_Fourier_transform_%28general%29#Number-theoretic_transform">
     *       Discrete Fourier Transform</a> (DFT) on the padded pieces.</li>
     *   <li>Calculate all pieces of z" by multiplying the i-th piece of a by the i-th piece of b.</li>
     *   <li>Perform an Inverse Discrete Fourier Transform (IDFT) on z". z" will contain all pieces of
     *       a*b mod Fn where Fn=2^2^n+1.</li>
     *   <li>Calculate all pieces of z such that each piece is congruent to z' modulo n+2 and congruent to
     *       z" modulo Fn. This is done using the
     *       <a href="http://en.wikipedia.org/wiki/Chinese_remainder_theorem">Chinese remainder theorem</a>.</li>
     *   <li>Calculate c by adding z_i * 2^(i*2^(n-1)) for all i, where z_i is the i-th piece of z.</li>
     *   <li>Return c reduced modulo 2^2^m+1.</li>
     * </ol>
     * @param a
     * @param aBitLen
     * @param b
     * @param bBitLen
     * @return a*b
     */
    private static int[] mult(int[] a, int aBitLen, int[] b, int bBitLen) {
        if (!shouldUseSchönhageStrassen(Math.max(aBitLen, bBitLen)))
            return multKaratsuba(a, b);
        
        // set M to the number of binary digits in a or b, whichever is greater
        int M = Math.max(aBitLen, bBitLen);
        
        // find the lowest m such that m>=log2(2M)
        int m = 32 - Integer.numberOfLeadingZeros(2*M-1-1);
        
        int n = m/2 + 1;
        
        // split a and b into pieces 1<<(n-1) bits long; assume n>=6 so pieces start and end at int boundaries
        boolean even = m%2 == 0;
        int numPieces = even ? 1<<n : 1<<(n+1);
        int pieceSize = 1 << (n-1-5);   // in ints
        
        // build u and v from a and b, allocating 3n+5 bits in u and v per n+2 bits from a and b, resp.
        int numPiecesA = (a.length+pieceSize) / pieceSize;
        int[] u = new int[(numPiecesA*(3*n+5)+31)/32];
        int uBitLength = 0;
        for (int i=0; i<numPiecesA && i*pieceSize<a.length; i++) {
            appendBits(u, uBitLength, a, i*pieceSize, n+2);
            uBitLength += 3*n+5;
        }
        int numPiecesB = (b.length+pieceSize) / pieceSize;
        int[] v = new int[(numPiecesB*(3*n+5)+31)/32];
        int vBitLength = 0;
        for (int i=0; i<numPiecesB && i*pieceSize<b.length; i++) {
            appendBits(v, vBitLength, b, i*pieceSize, n+2);
            vBitLength += 3*n+5;
        }
        
        int[] gamma = mult(u, uBitLength, v, vBitLength);
        int[][] gammai = splitBits(gamma, 3*n+5);
        int halfNumPcs = numPieces / 2;
        
        int[][] zi = new int[gammai.length][];
        for (int i=0; i<gammai.length; i++)
            zi[i] = gammai[i];
        for (int i=0; i<gammai.length-halfNumPcs; i++)
            subModPow2(zi[i], gammai[i+halfNumPcs], n+2);
        for (int i=0; i<gammai.length-2*halfNumPcs; i++)
            addModPow2(zi[i], gammai[i+2*halfNumPcs], n+2);
        for (int i=0; i<gammai.length-3*halfNumPcs; i++)
            subModPow2(zi[i], gammai[i+3*halfNumPcs], n+2);
        
        // zr mod Fn
        int[][] ai = splitInts(a, halfNumPcs, pieceSize, 1<<(n+1-5));
        int[][] bi = splitInts(b, halfNumPcs, pieceSize, 1<<(n+1-5));
        dft(ai, m, n);
        dft(bi, m, n);
        modFn(ai);
        modFn(bi);
        int[][] c = new int[halfNumPcs][];
        for (int i=0; i<c.length; i++)
            c[i] = multModFn(ai[i], bi[i]);
        idft(c, m, n);
        modFn(c);

        int[] z = new int[1<<(m+1-5)];
        // calculate zr mod Fm from zr mod Fn and zr mod 2^(n+2), then add to z
        for (int i=0; i<halfNumPcs; i++) {
            int[] eta = i>=zi.length ? new int[(n+2+31)/32] : zi[i];
            
            // zi = delta = (zi-c[i]) % 2^(n+2)
            subModPow2(eta, c[i], n+2);
            
            // z += zr<<shift = [ci + delta*(2^2^n+1)] << [i*2^(n-1)]
            int shift = i*(1<<(n-1-5));   // assume n>=6
            addShifted(z, c[i], shift);
            addShifted(z, eta, shift);
            addShifted(z, eta, shift+(1<<(n-5)));
        }
        
        modFn(z);   // assume m>=5
        return z;
    }
    
    /**
     * Estimates whether SS or Karatsuba will be more efficient when multiplying two numbers
     * of a given length in bits.
     * @param bitLength the number of bits in each of the two factors
     * @return <code>true</code> if SS is more efficient, <code>false</code> if Karatsuba is more efficient
     */
    private static boolean shouldUseSchönhageStrassen(int bitLength) {
        // The following values were determined experimentally on a 32-bit JVM.
        if (bitLength < 93600)
            return false;
        if (bitLength < 131072)
            return true;
        if (bitLength < 159300)
            return false;
        return true;
    }
    
    /**
     * Performs a
     * <a href="http://en.wikipedia.org/wiki/Discrete_Fourier_transform_%28general%29#Number-theoretic_transform">
     * Fermat Number Transform</a> on an array whose elements are <code>int</code> arrays.<br/>
     * <code>A</code> is assumed to be the lower half of the full array and the upper half is assumed to be all zeros.
     * The number of subarrays in <code>A</code> must be 2^n if m is even and 2^(n+1) if m is odd.<br/>
     * Each subarray must be ceil(2^(n-1)) bits in length.<br/>
     * n must be equal to m/2-1.
     * @param A
     * @param m
     * @param n
     */
    static void dft(int[][] A, int m, int n) {
        boolean even = m%2 == 0;
        int len = A.length;
        int v = 1;
        
        for (int slen=len/2; slen>0; slen/=2) {   // slen = #consecutive coefficients for which the sign (add/sub) and x are constant
            for (int j=0; j<len; j+=2*slen) {
                int idx = j;
                int x = getDftExponent(n, v, idx+len, even);
                
                for (int k=slen-1; k>=0; k--) {
                    int[] d = cyclicShiftLeftBits(A[idx+slen], x);
                    System.arraycopy(A[idx], 0, A[idx+slen], 0, A[idx].length);   // copy A[idx] into A[idx+slen]
                    addModFn(A[idx], d);
                    subModFn(A[idx+slen], d, 1<<n);
                    idx++;
                }
            }
            
            v++;
        }
    }
    
    /**
     * Returns the power to which to raise omega in a DFT.<br/>
     * Omega itself is either 2 or 4 depending on m, but when omega=4 this method
     * doubles the exponent so omega can be assumed always to be 2 in a DFT.
     * @param n
     * @param v
     * @param idx
     * @param even
     * @return
     */
    private static int getDftExponent(int n, int v, int idx, boolean even) {
        // take bits n-v..n-1 of idx, reverse them, shift left by n-v-1
        int x = Integer.reverse(idx) << (n-v) >>> (31-n);
        
        // if m is even, divide by two
        if (even)
            x >>>= 1;
        
        return x;
    }
    
    /**
     * Performs a modified
     * <a href="http://en.wikipedia.org/wiki/Discrete_Fourier_transform_%28general%29#Number-theoretic_transform">
     * Inverse Fermat Number Transform</a> on an array whose elements are <code>int</code> arrays.
     * The modification is that the last step (the one where the upper half is subtracted from the lower half)
     * is omitted.<br/>
     * <code>A</code> is assumed to be the upper half of the full array and the upper half is assumed to be all zeros.
     * The number of subarrays in <code>A</code> must be 2^n if m is even and 2^(n+1) if m is odd.<br/>
     * Each subarray must be ceil(2^(n-1)) bits in length.<br/>
     * n must be equal to m/2-1.
     * @param A
     * @param m
     * @param n
     */
    static void idft(int[][] A, int m, int n) {
        boolean even = m%2 == 0;
        int len = A.length;
        int v = n - 1;
        int[] c = new int[A[0].length];
        
        for (int slen=1; slen<=len/2; slen*=2) {   // slen = #consecutive coefficients for which the sign (add/sub) and x are constant
            for (int j=0; j<len; j+=2*slen) {
                int idx = j;
                int idx2 = idx + slen;   // idx2 is always idx+slen
                int x = getIdftExponent(n, v, idx, even);
                
                for (int k=slen-1; k>=0; k--) {
                    System.arraycopy(A[idx], 0, c, 0, c.length);   // copy A[idx] into c
                    addModFn(A[idx], A[idx2]);
                    A[idx] = cyclicShiftRight(A[idx], 1);
                    
                    subModFn(c, A[idx2], 1<<n);
                    A[idx2] = cyclicShiftRight(c, x);
                    idx++;
                    idx2++;
                }
            }
            
            v--;
        }
    }
    
    /**
     * Returns the power to which to raise omega in an IDFT.<br/>
     * Omega itself is either 2 or 4 depending on m, but when omega=4 this method
     * doubles the exponent so omega can be assumed always to be 2 in a IDFT.
     * @param n
     * @param v
     * @param idx
     * @param even
     * @return
     */
    private static int getIdftExponent(int n, int v, int idx, boolean even) {
        int x = Integer.reverse(idx) << (n-v) >>> (32-n);
        x += even ? 1<<(n-v) : 1<<(n-1-v);
        return x + 1;
    }
    
    /**
     * Adds two <b>positive</b> numbers (meaning they are interpreted as unsigned) modulo 2^2^n+1,
     * where n is <code>a.length*32/2</code>; in other words, n is half the number of bits in
     * <code>a</code>.<br/>
     * Both input values are given as <code>int</code> arrays; they must be the same length.
     * The result is returned in the first argument.
     * @param a a number in base 2^32 starting with the lowest digit; the length must be a power of 2
     * @param b a number in base 2^32 starting with the lowest digit; the length must be a power of 2
     */
    static void addModFn(int[] a, int[] b) {
        boolean carry = false;
        for (int i=0; i<a.length; i++) {
            int sum = a[i] + b[i];
            if (carry)
                sum++;
            carry = ((sum>>>31) < (a[i]>>>31)+(b[i]>>>31));   // carry if signBit(sum) < signBit(a)+signBit(b)
            a[i] = sum;
        }
        
        // take a mod Fn by adding any remaining carry bit to the lowest bit;
        // since Fn ≡ 1 (mod 2^n), it suffices to add 1
        int i = 0;
        while (carry) {
            int sum = a[i] + 1;
            a[i] = sum;
            carry = sum == 0;
            i++;
            if (i >= a.length)
                i = 0;
        }
    }
    
    /**
     * Subtracts two <b>positive</b> numbers (meaning they are interpreted as unsigned) modulo 2^2^n+1,
     * where n is <code>a.length*32/2</code>; in other words, n is half the number of bits in
     * <code>a</code>.<br/>
     * Both input values are given as <code>int</code> arrays; they must be the same length.
     * The result is returned in the first argument.
     * @param a a number in base 2^32 starting with the lowest digit; the length must be a power of 2
     * @param b a number in base 2^32 starting with the lowest digit; the length must be a power of 2
     */
    private static void subModFn(int[] a, int[] b, int pow2n) {
        addModFn(a, cyclicShiftLeftElements(b, pow2n/32));
    }
    
    /**
     * Multiplies two <b>positive</b> numbers (meaning they are interpreted as unsigned) modulo Fn
     * where Fn=2^2^n+1, and returns the result in a new array.<br/>
     * <code>a</code> and <code>b</code> are assumed to be reduced mod Fn, i.e. 0<=a<Fn and 0<=b<Fn,
     * where n is <code>a.length*32/2</code>; in other words, n is half the number of bits in
     * <code>a</code>.<br/>
     * Both input values are given as <code>int</code> arrays; they must be the same length.
     * @param a a number in base 2^32 starting with the lowest digit; the length must be a power of 2
     * @param b a number in base 2^32 starting with the lowest digit; the length must be a power of 2
     */
    static int[] multModFn(int[] a, int[] b) {
        int[] a0 = Arrays.copyOf(a, a.length/2);
        int[] b0 = Arrays.copyOf(b, b.length/2);
        int[] c = mult(a0, b0);
        int n = a.length/2;
        // special case: if a=Fn-1, add b*2^2^n which is the same as subtracting b
        if (a[n] == 1)
            subModFn(c, Arrays.copyOf(b0, c.length), n*32);
        if (b[n] == 1)
            subModFn(c, Arrays.copyOf(a0, c.length), n*32);
        return c;
    }
    
    static void modFn(int[] a) {
        int len = a.length;
        boolean carry = false;
        for (int i=0; i<len/2; i++) {
            int bi = a[len/2+i];
            int diff = a[i] - bi;
            if (carry)
                diff--;
            carry = ((diff>>>31) > (a[i]>>>31)-(bi>>>31));   // carry if signBit(diff) > signBit(a)-signBit(b)
            a[i] = diff;
        }
        for (int i=len/2; i<len; i++)
            a[i] = 0;
        // if result is negative, add Fn; since Fn ≡ 1 (mod 2^n), it suffices to add 1
        if (carry) {
            int j = 0;
            do {
                int sum = a[j] + 1;
                a[j] = sum;
                carry = sum == 0;
                j++;
                if (j >= a.length)
                    j = 0;
            } while (carry);
        }
    }
    
    /**
     * Reduces all subarrays modulo 2^2^n+1 where n=<code>a[i].length*32/2</code> for all i;
     * in other words, n is half the number of bits in the subarray.
     * @param a int arrays whose length is a power of 2
     */
    static void modFn(int[][] a) {
        for (int i=0; i<a.length; i++)
            modFn(a[i]);
    }
    
    /**
     * Cyclicly shifts a number to the right modulo 2^2^n+1 and returns the result in a new array.
     * "Right" means towards the lower array indices and the lower bits; this is equivalent to
     * a multiplication by 2^(-numBits) modulo 2^2^n+1.<br/>
     * The number n is <code>a.length*32/2</code>; in other words, n is half the number of bits in
     * <code>a</code>.<br/>
     * Both input values are given as <code>int</code> arrays; they must be the same length.
     * The result is returned in the first argument.
     * @param a a number in base 2^32 starting with the lowest digit; the length must be a power of 2
     * @param numBits the shift amount in bits
     * @return the shifted number
     */
    static int[] cyclicShiftRight(int[] a, int numBits) {
        int[] b = new int[a.length];
        int numElements = numBits / 32;
        System.arraycopy(a, numElements, b, 0, a.length-numElements);
        System.arraycopy(a, 0, b, a.length-numElements, numElements);
        
        numBits = numBits % 32;
        if (numBits != 0) {
            int b0 = b[0];
            b[0] = b[0] >>> numBits;
            for (int i=1; i<b.length; i++) {
                b[i-1] |= b[i] << (32-numBits);
                b[i] = b[i] >>> numBits;
            }
            b[b.length-1] |= b0 << (32-numBits);
        }
        return b;
    }
    
    /**
     * Shifts a number to the left modulo 2^2^n+1 and returns the result in a new array.
     * "Left" means towards the lower array indices and the lower bits; this is equivalent to
     * a multiplication by 2^numBits modulo 2^2^n+1.<br/>
     * The number n is <code>a.length*32/2</code>; in other words, n is half the number of bits in
     * <code>a</code>.<br/>
     * Both input values are given as <code>int</code> arrays; they must be the same length.
     * The result is returned in the first argument.
     * @param a a number in base 2^32 starting with the lowest digit; the length must be a power of 2
     * @param numBits the shift amount in bits
     * @return the shifted number
     */
    static int[] cyclicShiftLeftBits(int[] a, int numBits) {
        int[] b = cyclicShiftLeftElements(a, numBits/32);
        
        numBits = numBits % 32;
        if (numBits != 0) {
            int bhi = b[b.length-1];
            b[b.length-1] <<= numBits;
            for (int i=b.length-1; i>0; i--) {
                b[i] |= b[i-1] >>> (32-numBits);
                b[i-1] <<= numBits;
            }
            b[0] |= bhi >>> (32-numBits);
        }
        return b;
    }
    
    /**
     * Cyclicly shifts an array towards the higher indices by <code>numElements</code>
     * elements and returns the result in a new array.
     * @param a
     * @param numElements
     * @return
     */
    static int[] cyclicShiftLeftElements(int[] a, int numElements) {
        int[] b = new int[a.length];
        System.arraycopy(a, 0, b, numElements, a.length-numElements);
        System.arraycopy(a, a.length-numElements, b, 0, numElements);
        return b;
    }
    
    /**
     * Adds two numbers, <code>a</code> and <code>b</code>, after shifting <code>b</code> by
     * <code>numElements</code> elements.<br/>
     * Both numbers are given as <code>int</code> arrays and must be <b>positive</b> numbers
     * (meaning they are interpreted as unsigned).</br> The result is returned in the first
     * argument.
     * If any elements of b are shifted outside the valid range for <code>a</code>, they are dropped.
     * @param a a number in base 2^32 starting with the lowest digit
     * @param b a number in base 2^32 starting with the lowest digit
     * @param numElements
     */
    static void addShifted(int[] a, int[] b, int numElements) {
        boolean carry = false;
        int i = 0;
        while (i < Math.min(b.length, a.length-numElements)) {
            int ai = a[i+numElements];
            int sum = ai + b[i];
            if (carry)
                sum++;
            carry = ((sum>>>31) < (ai>>>31)+(b[i]>>>31));   // carry if signBit(sum) < signBit(a)+signBit(b)
            a[i+numElements] = sum;
            i++;
        }
        while (carry) {
            a[i+numElements]++;
            carry = a[i+numElements] == 0;
            i++;
        }
    }
    
    /**
     * Adds two <b>positive</b> numbers (meaning they are interpreted as unsigned) modulo 2^numBits.
     * Both input values are given as <code>int</code> arrays.
     * The result is returned in the first argument.
     * @param a a number in base 2^32 starting with the lowest digit
     * @param b a number in base 2^32 starting with the lowest digit
     */
    private static void addModPow2(int[] a, int[] b, int numBits) {
        int numElements = (numBits+31) / 32;
        boolean carry = false;
        int i;
        for (i=0; i<numElements; i++) {
            int sum = a[i] + b[i];
            if (carry)
                sum++;
            carry = ((sum>>>31) < (a[i]>>>31)+(b[i]>>>31));   // carry if signBit(sum) < signBit(a)+signBit(b)
            a[i] = sum;
        }
        a[i-1] &= -1 >>> (32-(numBits%32));
        for (; i<a.length; i++)
            a[i] = 0;
    }
    
    /**
     * Subtracts two <b>positive</b> numbers (meaning they are interpreted as unsigned) modulo 2^numBits.
     * Both input values are given as <code>int</code> arrays.
     * The result is returned in the first argument.
     * @param a a number in base 2^32 starting with the lowest digit
     * @param b a number in base 2^32 starting with the lowest digit
     */
    static void subModPow2(int[] a, int[] b, int numBits) {
        int numElements = (numBits+31) / 32;
        boolean carry = false;
        int i;
        for (i=0; i<numElements; i++) {
            int diff = a[i] - b[i];
            if (carry)
                diff--;
            carry = ((diff>>>31) > (a[i]>>>31)-(b[i]>>>31));   // carry if signBit(diff) > signBit(a)-signBit(b)
            a[i] = diff;
        }
        a[i-1] &= -1 >>> (32-(numBits%32));
        for (; i<a.length; i++)
            a[i] = 0;
    }
    
    /**
     * Reads <code>bBitLength</code> bits from <code>b</code>, starting at array index
     * <code>bStart</code>, and copies them into <code>a</code>, starting at bit
     * <code>aBitLength</code>. The result is returned in <code>a</code>.
     * @param a
     * @param aBitLength
     * @param b
     * @param bStart
     * @param bBitLength
     */
    static void appendBits(int[] a, int aBitLength, int[] b, int bStart, int bBitLength) {
        int aIdx = aBitLength / 32;
        int bit32 = aBitLength % 32;
        
        for (int i=bStart; i<bStart+bBitLength/32; i++) {
            if (bit32 > 0) {
                a[aIdx] |= b[i] << bit32;
                aIdx++;
                a[aIdx] = b[i] >>> (32-bit32);
            }
            else {
                a[aIdx] = b[i];
                aIdx++;
            }
        }
        
        if (bBitLength%32 > 0) {
            int bIdx = bBitLength / 32;
            int bi = b[bStart+bIdx];
            bi &= -1 >>> (32-bBitLength);
            a[aIdx] |= bi << bit32;
            if (bit32+(bBitLength%32) > 32)
                a[aIdx+1] = bi >>> (32-bit32);
        }
    }
    
    /**
     * Divides an <code>int</code> array into pieces <code>bitLength</code> bits long.
     * @param a
     * @param bitLength
     * @return a new array containing <code>bitLength</code> bits from <code>a</code> in each subarray
     */
    private static int[][] splitBits(int[] a, int bitLength) {
        int aIntIdx = 0;
        int aBitIdx = 0;
        int numPieces = (a.length*32+bitLength-1) / bitLength;
        int pieceLength = (bitLength+31) / 32;   // in ints
        int[][] b = new int[numPieces][pieceLength];
        for (int i=0; i<b.length; i++) {
            int bitsRemaining = Math.min(bitLength, a.length*32-i*bitLength);
            int bIntIdx = 0;
            int bBitIdx = 0;
            while (bitsRemaining > 0) {
                int bitsToCopy = Math.min(32-aBitIdx, 32-bBitIdx);
                bitsToCopy = Math.min(bitsRemaining, bitsToCopy);
                int mask = a[aIntIdx] >>> aBitIdx;
                mask &= -1 >>> (32-bitsToCopy);
                mask <<= bBitIdx;
                b[i][bIntIdx] |= mask;
                bitsRemaining -= bitsToCopy;
                aBitIdx += bitsToCopy;
                if (aBitIdx >= 32) {
                    aBitIdx -= 32;
                    aIntIdx++;
                }
                bBitIdx += bitsToCopy;
                if (bBitIdx >= 32) {
                    bBitIdx -= 32;
                    bIntIdx++;
                }
            }
        }
        return b;
    }
    
    /**
     * Splits an <code>int</code> array into pieces of <code>pieceSize ints</code> each, and
     * pads each piece to <code>targetPieceSize ints</code>.
     * @param a the input array
     * @param numPieces the number of pieces to split the array into
     * @param pieceSize the size of each piece in the input array in <code>ints</code>
     * @param targetPieceSize the size of each piece in the output array in <code>ints</code>
     * @return an array of length <code>numPieces</code> containing subarrays of length <code>targetPieceSize</code>
     */
    private static int[][] splitInts(int[] a, int numPieces, int pieceSize, int targetPieceSize) {
        int[][] ai = new int[numPieces][targetPieceSize];
        for (int i=0; i<a.length/pieceSize; i++)
            System.arraycopy(a, i*pieceSize, ai[i], 0, pieceSize);
        System.arraycopy(a, a.length/pieceSize*pieceSize, ai[a.length/pieceSize], 0, a.length%pieceSize);
        return ai;
    }
    
    /**
     * Multiplies two <b>positive</b> numbers represented as <code>int</code> arrays using the
     * <a href="http://en.wikipedia.org/wiki/Karatsuba_algorithm">Karatsuba algorithm</a>.
     */
    static int[] multKaratsuba(int[] a, int[] b) {
        int n = Math.max(a.length, b.length);
        if (n <= KARATSUBA_THRESHOLD)
            return multSimple(a, b);
        else {
            int n1 = (n+1) / 2;
            int n1a = Math.min(n1, a.length);
            int n1b = Math.min(n1, b.length);
            
            int[] a1 = Arrays.copyOf(a, n1a);
            int[] a2 = n1a>=a.length ? new int[0] : Arrays.copyOfRange(a, n1a, n);
            int[] b1 = Arrays.copyOf(b, n1);
            int[] b2 = n1b>=b.length ? new int[0] : Arrays.copyOfRange(b, n1b, n);
            
            int[] A = addExpand(a1, a2);
            int[] B = addExpand(b1, b2);
            
            int[] c1 = multKaratsuba(a1, b1);
            int[] c2 = multKaratsuba(a2, b2);
            int[] c3 = multKaratsuba(A, B);
            c3 = subExpand(c3, c1);   // c3-c1>0 because a and b are positive
            c3 = subExpand(c3, c2);   // c3-c2>0 because a and b are positive
            
            int[] c = Arrays.copyOf(c1, Math.max(n1+c3.length, 2*n1+c2.length));
            addShifted(c, c3, n1);
            addShifted(c, c2, 2*n1);
            
            return c;
        }
    }
    
    /**
     * Adds two <b>positive</b> numbers (meaning they are interpreted as unsigned) that are given as
     * <code>int</code> arrays and returns the result in a new array. The result may be one longer
     * than the input due to a carry.
     * @param a a number in base 2^32 starting with the lowest digit
     * @param b a number in base 2^32 starting with the lowest digit
     * @return the sum
     */
    private static int[] addExpand(int[] a, int[] b) {
        int[] c = Arrays.copyOf(a, Math.max(a.length, b.length));
        boolean carry = false;
        int i = 0;
        while (i < Math.min(b.length, a.length)) {
            int sum = a[i] + b[i];
            if (carry)
                sum++;
            carry = ((sum>>>31) < (a[i]>>>31)+(b[i]>>>31));   // carry if signBit(sum) < signBit(a)+signBit(b)
            c[i] = sum;
            i++;
        }
        while (carry) {
            if (i == c.length)
                c = Arrays.copyOf(c, c.length+1);
            c[i]++;
            carry = c[i] == 0;
            i++;
        }
        return c;
    }
    
    /**
     * Subtracts two <b>positive</b> numbers (meaning they are interpreted as unsigned) that are given as
     * <code>int</code> arrays and returns the result in a new array.<br/>
     * <code>a</code> must be greater than or equal to <code>b</code>.
     * @param a a number in base 2^32 starting with the lowest digit
     * @param b a number in base 2^32 starting with the lowest digit
     * @return the difference
     */
    private static int[] subExpand(int[] a, int[] b) {
        int[] c = Arrays.copyOf(a, Math.max(a.length, b.length));
        boolean carry = false;
        int i = 0;
        while (i < Math.min(b.length, a.length)) {
            int diff = a[i] - b[i];
            if (carry)
                diff--;
            carry = ((diff>>>31) > (a[i]>>>31)-(b[i]>>>31));   // carry if signBit(diff) > signBit(a)-signBit(b)
            c[i] = diff;
            i++;
        }
        while (carry) {
            c[i]--;
            carry = c[i] == -1;
            i++;
        }
        return c;
    }
    
    /**
     * Multiplies two <b>positive</b> numbers (meaning they are interpreted as unsigned) represented as
     * <code>int</code> arrays using the simple O(n²) algorithm.
     * @param a a number in base 2^32 starting with the lowest digit
     * @param b a number in base 2^32 starting with the lowest digit
     * @return the product
     */
    static int[] multSimple(int[] a, int[] b) {
        int[] c = new int[a.length+b.length];
        long carry = 0;
        for (int i=0; i<c.length; i++) {
            long ci = c[i] & 0xFFFFFFFFL;
            for (int k=Math.max(0,i-b.length+1); k<a.length&&k<=i; k++) {
                long prod = (a[k]&0xFFFFFFFFL) * (b[i-k]&0xFFFFFFFFL);
                ci += prod;
                carry += ci >>> 32;
                ci = ci << 32 >>> 32;
            }
            c[i] = (int)ci;
            if (i < c.length-1)
                c[i+1] = (int)carry;
            carry >>>= 32;
        }
        return c;
    }
    
    
    /**
     * Converts a {@link BigInteger} to an <code>int</code> array.
     * @param a
     * @return an <code>int</code> array that is compatible with the <code>mult()</code> methods
     */
    public static int[] toIntArray(BigInteger a) {
        byte[] aArr = a.toByteArray();
        int[] b = new int[(aArr.length+3)/4];
        for (int i=0; i<aArr.length; i++)
            b[i/4] += (aArr[aArr.length-1-i]&0xFF) << ((i%4)*8);
        return b;
    }
    
    /**
     * Converts a <code>int</code> array to a {@link BigInteger}.
     * @param a
     * @return the <code>BigInteger</code> representation of the array
     */
    public static BigInteger toBigInteger(int[] a) {
        byte[] b = new byte[a.length*4];
        for (int i=0; i<a.length; i++) {
            int iRev = a.length - 1 - i;
            b[i*4] = (byte)(a[iRev] >>> 24);
            b[i*4+1] = (byte)((a[iRev]>>>16) & 0xFF);
            b[i*4+2] = (byte)((a[iRev]>>>8) & 0xFF);
            b[i*4+3] = (byte)(a[iRev] & 0xFF);
        }
        return new BigInteger(1, b);
    }
}