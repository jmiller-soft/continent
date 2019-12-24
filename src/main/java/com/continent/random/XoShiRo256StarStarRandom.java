package com.continent.random;

import java.io.File;
import java.io.IOException;

/*
 * DSI utilities
 *
 * Copyright (C) 2013-2018 Sebastiano Vigna
 *
 *  This library is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as published by the Free
 *  Software Foundation; either version 3 of the License, or (at your option)
 *  any later version.
 *
 *  This library is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 *  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.crypto.prng.RandomGenerator;

import com.google.common.io.Files;

/** A fast, all-purpose, rock-solid {@linkplain Random pseudorandom number generator}. It has excellent speed, a state space (256 bits) that is large enough for
 * any parallel application, and it passes all tests we are aware of. More information can be found at our <a href="http://prng.di.unimi.it/">PRNG page</a>.
 *
 * <p>If you need to generate just floating-point numbers, {@link XoShiRo256PlusRandom} is slightly faster. If you are tight on space,
 * you might try {@link XoRoShiRo128StarStarRandom}.
 *
 * <p>By using the supplied {@link #jump()} method it is possible to generate non-overlapping long sequences
 * for parallel computations. This class provides also a {@link #split()} method to support recursive parallel computations, in the spirit of
 * {@link SplittableRandom}.
 *
 * <p>Note that this is not a {@linkplain SecureRandom secure generator}.
 *
 * @version 1.0
 * @see it.unimi.dsi.util
 * @see RandomGenerator
 * @see XoShiRo256StarStarRandomGenerator
 */


public class XoShiRo256StarStarRandom extends Random {
    private static final long serialVersionUID = 1L;
    /** The internal state of the algorithm. */
    private long s0, s1, s2, s3;

    /** Creates a new generator using a given seed.
     *
     * @param seed a seed for the generator.
     */
    public XoShiRo256StarStarRandom(final long seed) {
        setSeed(seed);
    }

    @Override
    public long nextLong() {
        long result = s1;
        result = Long.rotateLeft(result + (result << 2), 7);
        result += result << 3;

        final long t = s1 << 17;

        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;

        s2 ^= t;

        s3 = Long.rotateLeft(s3, 45);

        return result;
    }

    @Override
    public int nextInt() {
        return (int)nextLong();
    }

    @Override
    public int nextInt(final int n) {
        return (int)nextLong(n);
    }

    /** Returns a pseudorandom uniformly distributed {@code long} value
     * between 0 (inclusive) and the specified value (exclusive), drawn from
     * this random number generator's sequence. The algorithm used to generate
     * the value guarantees that the result is uniform, provided that the
     * sequence of 64-bit values produced by this generator is.
     *
     * @param n the positive bound on the random number to be returned.
     * @return the next pseudorandom {@code long} value between {@code 0} (inclusive) and {@code n} (exclusive).
     */
    public long nextLong(final long n) {
        if (n <= 0) throw new IllegalArgumentException("illegal bound " + n + " (must be positive)");
        long t = nextLong();
        final long nMinus1 = n - 1;
        // Rejection-based algorithm to get uniform integers in the general case
        for (long u = t >>> 1; u + nMinus1 - (t = u % n) < 0; u = nextLong() >>> 1);
        return t;
    }

    @Override
    public double nextDouble() {
        return (nextLong() >>> 11) * 0x1.0p-53;
    }

    /**
     * Returns the next pseudorandom, uniformly distributed
     * {@code double} value between {@code 0.0} and
     * {@code 1.0} from this random number generator's sequence,
     * using a fast multiplication-free method which, however,
     * can provide only 52 significant bits.
     *
     * <p>This method is faster than {@link #nextDouble()}, but it
     * can return only dyadic rationals of the form <var>k</var> / 2<sup>&minus;52</sup>,
     * instead of the standard <var>k</var> / 2<sup>&minus;53</sup>. Before
     * version 2.4.1, this was actually the standard implementation of
     * {@link #nextDouble()}, so you can use this method if you need to
     * reproduce exactly results obtained using previous versions.
     *
     * <p>The only difference between the output of this method and that of
     * {@link #nextDouble()} is an additional least significant bit set in half of the
     * returned values. For most applications, this difference is negligible.
     *
     * @return the next pseudorandom, uniformly distributed {@code double}
     * value between {@code 0.0} and {@code 1.0} from this
     * random number generator's sequence, using 52 significant bits only.
     */
    public double nextDoubleFast() {
        return Double.longBitsToDouble(0x3FFL << 52 | nextLong() >>> 12) - 1.0;
    }

    @Override
    public float nextFloat() {
        return (nextLong() >>> 40) * 0x1.0p-24f;
    }

    @Override
    public boolean nextBoolean() {
        return nextLong() < 0;
    }

    @Override
    public void nextBytes(final byte[] bytes) {
        int i = bytes.length, n = 0;
        while(i != 0) {
            n = Math.min(i, 8);
            for (long bits = nextLong(); n-- != 0; bits >>= 8) bytes[--i] = (byte)bits;
        }
    }

    private static final long JUMP[] = { 0x180ec6d33cfd0abaL, 0xd5a61266f0c9392cL, 0xa9582618e03fc9aaL, 0x39abdc4529b1661cL };

    /** The jump function for this generator. It is equivalent to 2<sup>64</sup>
     * calls to {@link #nextLong()}; it can be used to generate 2<sup>64</sup>
     * non-overlapping subsequences for parallel computations. */

    public void jump() {
        long s0 = 0;
        long s1 = 0;
        long s2 = 0;
        long s3 = 0;
        for(int i = 0; i < JUMP.length; i++)
            for(int b = 0; b < 64; b++) {
                if ((JUMP[i] & 1L << b) != 0) {
                    s0 ^= this.s0;
                    s1 ^= this.s1;
                    s2 ^= this.s2;
                    s3 ^= this.s3;
                }
                nextLong();
            }

        this.s0 = s0;
        this.s1 = s1;
        this.s2 = s2;
        this.s3 = s3;
    }

    /**
     * Returns a new instance that shares no mutable state
     * with this instance. The sequence generated by the new instance
     * depends deterministically from the state of this instance,
     * but the probability that the sequence generated by this
     * instance and by the new instance overlap is negligible.
     *
     * @return the new instance.
     */
    public XoShiRo256StarStarRandom split() {
        final XoShiRo256StarStarRandom split = new XoShiRo256StarStarRandom(nextLong());
        split.s0 = HashCommon.murmurHash3(s0);
        split.s1 = HashCommon.murmurHash3(s1);
        split.s2 = HashCommon.murmurHash3(s2);
        split.s3 = HashCommon.murmurHash3(s3);
        return split;
    }
    
    /** Sets the seed of this generator.
     *
     * <p>The argument will be used to seed a {@link SplitMix64RandomGenerator}, whose output
     * will in turn be used to seed this generator. This approach makes &ldquo;warmup&rdquo; unnecessary,
     * and makes the probability of starting from a state
     * with a large fraction of bits set to zero astronomically small.
     *
     * @param seed a seed for this generator.
     */
    @Override
    public void setSeed(final long seed) {
        final SplitMix64RandomGenerator r = new SplitMix64RandomGenerator(seed);
        s0 = r.nextLong();
        s1 = r.nextLong();
        s2 = r.nextLong();
        s3 = r.nextLong();
    }


    /** Sets the state of this generator.
     *
     * <p>The internal state of the generator will be reset, and the state array filled with the provided array.
     *
     * @param state an array of 2 longs; at least one must be nonzero.
     */
    public void setState(final long[] state) {
        if (state.length != 4) throw new IllegalArgumentException("The argument array contains " + state.length + " longs instead of " + 2);
        s0 = state[0];
        s1 = state[1];
        s2 = state[2];
        s3 = state[3];
    }

    public static void main(final String[] arg) throws IOException {
        final XoShiRo256StarStarRandom r = new XoShiRo256StarStarRandom(0);
        byte[] bytes = new byte[1024*1024*10];
        r.nextBytes(bytes);
        Files.write(bytes, new File("C:\\Devel\\projects\\encryptor\\ent\\out1.rnd"));
        
        final XoShiRo256StarStarRandom r1 = r.split();
//        final SplittableRandom r1 = new SplittableRandom(0);
        byte[] bytes2 = new byte[1024*1024*10];
        r1.nextBytes(bytes2);
        Files.write(bytes2, new File("C:\\Devel\\projects\\encryptor\\ent\\out2.rnd"));

    }
}
