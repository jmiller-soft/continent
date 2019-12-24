package com.continent.random.entropy;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Please note: JVM should be run with follow params to disable JIT-optimization
 * which is important for random generation process
 * 
 * "-XX:CompileCommand=exclude,com/continent/random/entropy/JitterEntropy.*"
 * 
 *
 */
public class JitterEntropy implements EntropySource {

    protected static final int DATA_SIZE_BITS = Long.SIZE;
    private static final int MAX_ACC_LOOP_BIT = 7;
    private static final int MIN_ACC_LOOP_BIT = 0;
    private static final int MAX_FOLD_LOOP_BIT = 4;
    private static final int MIN_FOLD_LOOP_BIT = 0;

    public static class RandomData {

        long data;
        long oldData;
        long prevTime;

        long lastDelta;
        long lastDelta2;

        int osr = 1;
        int memblocks = 64;
        int memblocksize = 32;
        int memaccessloops = 128;
        int memlocation = 0;
        byte[] mem = new byte[memblocks * memblocksize];
    }

    protected final RandomData randomData = new RandomData();
    private AtomicBoolean stop;

    static {
        try {
            ClassLoader systemClassLoader = getSystemClassLoader();
            
            // Now try to get the JVM option (-XX:MaxDirectMemorySize) and parse it.
            // Note that we are using reflection because Android doesn't have these classes.
            Class<?> mgmtFactoryClass = Class.forName(
                    "java.lang.management.ManagementFactory", true, systemClassLoader);
            Class<?> runtimeClass = Class.forName(
                    "java.lang.management.RuntimeMXBean", true, systemClassLoader);

            Object runtime = mgmtFactoryClass.getDeclaredMethod("getRuntimeMXBean").invoke(null);

            @SuppressWarnings("unchecked")
            List<String> vmArgs = (List<String>) runtimeClass.getDeclaredMethod("getInputArguments").invoke(runtime);
            boolean found = false;
            String argument = "-XX:CompileCommand=exclude," + JitterEntropy.class.getName().replace(".", "/") + ".*";
            for (int i = vmArgs.size() - 1; i >= 0; i --) {
                String arg = vmArgs.get(i);
                if (arg.equals(argument)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new IllegalStateException("JitterEntropy hasn't been excluded from JIT compile!\nPlease add " + argument + " to JVM arguments");
            }
            
            JitterEntropy je = new JitterEntropy();
            je.check();
        } catch (Throwable e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        }
    }
    
    static ClassLoader getSystemClassLoader() {
        if (System.getSecurityManager() == null) {
            return ClassLoader.getSystemClassLoader();
        } else {
            return AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
                @Override
                public ClassLoader run() {
                    return ClassLoader.getSystemClassLoader();
                }
            });
        }
    }

    public JitterEntropy() {
    }
    
    public JitterEntropy(AtomicBoolean stop) {
        this.stop = stop;
    }

    private void check()
    {
        int i;
        long delta_sum = 0;
        long old_delta = 0;
        int time_backwards = 0;
        int count_mod = 0;
        int count_stuck = 0;
        RandomData ec = new RandomData();

        /* We could perform statistical tests here, but the problem is
         * that we only have a few loop counts to do testing. These
         * loop counts may show some slight skew and we produce
         * false positives.
         *
         * Moreover, only old systems show potentially problematic
         * jitter entropy that could potentially be caught here. But
         * the RNG is intended for hardware that is available or widely
         * used, but not old systems that are long out of favor. Thus,
         * no statistical tests.
         */

        /*
         * We could add a check for system capabilities such as clock_getres or
         * check for CONFIG_X86_TSC, but it does not make much sense as the
         * following sanity checks verify that we have a high-resolution
         * timer.
         */
        /*
         * TESTLOOPCOUNT needs some loops to identify edge systems. 100 is
         * definitely too little.
         */
        int TESTLOOPCOUNT = 300;
        int CLEARCACHE = 100;
        for (i = 0; (TESTLOOPCOUNT + CLEARCACHE) > i; i++) {
            long time = 0;
            long time2 = 0;
            long delta = 0;
            long lowdelta = 0;

            /* Invoke core entropy collection logic */
            time = System.nanoTime();
            ec.prevTime = time;
            
            lfsrTime(ec, time);
            
            time2 = System.nanoTime();

            /* test whether timer works */
            if (time == 0 || time2 == 0)
                throw new IllegalStateException("System.nanoTime doesn't work properly!");
            delta = time2 - time;
            /*
             * test whether timer is fine grained enough to provide
             * delta even when called shortly after each other -- this
             * implies that we also have a high resolution timer
             */
            if (delta == 0)
                throw new IllegalStateException("System.nanoTime doesn't work properly!");

            boolean stuck = isStuck(ec, delta);

            /*
             * up to here we did not modify any variable that will be
             * evaluated later, but we already performed some work. Thus we
             * already have had an impact on the caches, branch prediction,
             * etc. with the goal to clear it to get the worst case
             * measurements.
             */
            if (CLEARCACHE > i)
                continue;

            if (stuck)
                count_stuck++;

            /* test whether we have an increasing timer */
            if (!(time2 > time))
                time_backwards++;

            /* use 32 bit value to ensure compilation on 32 bit arches */
            lowdelta = time2 - time;
            if ((lowdelta % 100) == 0)
                count_mod++;

            /*
             * ensure that we have a varying delta timer which is necessary
             * for the calculation of entropy -- perform this check
             * only after the first loop is executed as we need to prime
             * the old_data value
             */
            if (delta > old_delta)
                delta_sum += (delta - old_delta);
            else
                delta_sum += (old_delta - delta);
            old_delta = delta;
        }

        /*
         * we allow up to three times the time running backwards.
         * CLOCK_REALTIME is affected by adjtime and NTP operations. Thus,
         * if such an operation just happens to interfere with our test, it
         * should not fail. The value of 3 should cover the NTP case being
         * performed during our test run.
         */
        if (3 < time_backwards)
            throw new IllegalStateException("Non monotonic timer!");

        /*
         * Variations of deltas of time must on average be larger
         * than 1 to ensure the entropy estimation
         * implied with 1 is preserved
         */
        if ((delta_sum) <= 1)
            throw new IllegalStateException("Variations of deltas of time must on average be larger than 1!");

        /*
         * Ensure that we have variations in the time stamp below 10 for at least
         * 10% of all checks -- on some platforms, the counter increments in
         * multiples of 100, but not always
         */
        if ((TESTLOOPCOUNT/10 * 9) < count_mod)
            throw new IllegalStateException("Less than 10% time stamps variations are below 10");

        /*
         * If we have more than 90% stuck results, then this Jitter RNG is
         * likely to not work well.
         */
        if (JENT_STUCK_INIT_THRES(TESTLOOPCOUNT) < count_stuck)
            throw new IllegalStateException("More than 90% stuck results!");
    }

    
    private int JENT_STUCK_INIT_THRES(int x) {
        return x/10 * 9;
    }
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InterruptedException {
        final ByteBuffer data = ByteBuffer.allocate(1024*1024);

        System.out.println(Runtime.getRuntime().availableProcessors());
        long s = System.currentTimeMillis();
        ExecutorService ex = Executors.newFixedThreadPool(5);
        final AtomicBoolean stop = new AtomicBoolean();
        for (int i = 0; i < 2; i++) {
            ex.execute(new Runnable() {
                @Override
                public void run() {
                    JitterEntropy e = new JitterEntropy(stop);
                    e.fill(data);
                }
            });
        }
        
        ScheduledExecutorService ss = Executors.newScheduledThreadPool(1);
        ss.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                if (data.position() > 1024*100) {
                    stop.set(true);
                }
            }
        }, 1, 1, TimeUnit.SECONDS);
        
        ex.shutdown();
        ex.awaitTermination(30, TimeUnit.MINUTES);
        
        int p = data.position();
        data.flip();
        System.out.println("limit " + data.limit());

        byte[] dst = new byte[p];
        data.get(dst);
        Files.write(Paths.get("C:\\Devel\\out3.rnd"), dst);
    }

    @Override
    public void fill(ByteBuffer randomBytes) {
        int len = randomBytes.limit();

        while ((stop != null && !stop.get()) || (stop == null && 0 < len)) {
//        while (0 < len) {
            int tocopy;

            genEntropy(randomData);

            if ((DATA_SIZE_BITS / 8) < len)
                tocopy = (DATA_SIZE_BITS / 8);
            else
                tocopy = len;

            synchronized (randomBytes) {
                randomBytes.putLong(randomData.data);
            }

            len -= tocopy;
        }
        
        /*
         * To be on the safe side, we generate one more round of entropy
         * which we do not give out to the caller. That round shall ensure
         * that in case the calling application crashes, memory dumps, pages
         * out, or due to the CPU Jitter RNG lingering in memory for long
         * time without being moved and an attacker cracks the application,
         * all he reads in the entropy pool is a value that is NEVER EVER
         * being used for anything. Thus, he does NOT see the previous value
         * that was returned to the caller for cryptographic purposes.
         */
        /*
         * If we use secured memory, do not use that precaution as the secure
         * memory protects the entropy pool. Moreover, note that using this
         * call reduces the speed of the RNG by up to half
         */
        genEntropy(randomData);
    }
    
    private void genEntropy(RandomData rd) {
        measureJitter(rd);

        long k = 0;
        while (true) {
            /* If a stuck measurement is received, repeat measurement */
            if (measureJitter(rd))
                continue;

            /*
             * We multiply the loop value with ->osr to obtain the oversampling
             * rate requested by the caller
             */
            if (++k >= (DATA_SIZE_BITS * rd.osr)) {
                break;
            }
        }
    }

    /**
     * This is the heart of the entropy generation: calculate time deltas and
     * use the CPU jitter in the time deltas. The jitter is injected into the
     * entropy pool.
     *
     * WARNING: ensure that ->prev_time is primed before using the output
     *      of this function! This can be done by calling this function
     *      and not using its result.
     *
     * Input:
     * @entropy_collector Reference to entropy collector
     *
     * @return: result of stuck test
     */    
    protected boolean measureJitter(RandomData rd) {
        long time = 0;
        long currentDelta = 0;

        /* Invoke one noise source before time measurement to add variations */
        memAccess(rd);
        
        /*
         * Get time stamp and calculate time delta to previous
         * invocation to measure the timing variations
         */        
        time = System.nanoTime();
        currentDelta = time - rd.prevTime;
        rd.prevTime = time;

        /* Now call the next noise sources which also injects the data */
        lfsrTime(rd, currentDelta);

        /* Check whether we have a stuck measurement. */
        boolean stuck = isStuck(rd, currentDelta);

        /*
         * Rotate the data buffer by a prime number (any odd number would
         * do) to ensure that every bit position of the input time stamp
         * has an even chance of being merged with a bit position in the
         * entropy pool. We do not use one here as the adjacent bits in
         * successive time deltas may have some form of dependency. The
         * chosen value of 7 implies that the low 7 bits of the next
         * time delta value is concatenated with the current time delta.
         */        
//        if (!stuck)
//            rd.data = rol64(rd.data, 7);

        return stuck;
    }

    /**
     * Stuck test by checking the:
     *  1st derivation of the jitter measurement (time delta)
     *  2nd derivation of the jitter measurement (delta of time deltas)
     *  3rd derivation of the jitter measurement (delta of delta of time deltas)
     *
     * All values must always be non-zero.
     *
     * Input:
     * @ec Reference to entropy collector
     * @current_delta Jitter time delta
     *
     * @return
     *  0 jitter measurement not stuck (good bit)
     *  1 jitter measurement stuck (reject bit)
     */    
    private boolean isStuck(RandomData rd, long currentDelta) {
        long delta2 = rd.lastDelta - currentDelta;
        long delta3 = delta2 - rd.lastDelta2;

        rd.lastDelta = currentDelta;
        rd.lastDelta2 = delta2;

        if (currentDelta == 0 || delta2 == 0 || delta3 == 0)
            return true;

        return false;
    }

    /**
     * CPU Jitter noise source -- this is the noise source based on the CPU
     *                execution time jitter
     *
     * This function injects the individual bits of the time value into the
     * entropy pool using an LFSR.
     *
     * The code is deliberately inefficient with respect to the bit shifting
     * and shall stay that way. This function is the root cause why the code
     * shall be compiled without optimization. This function not only acts as
     * folding operation, but this function's execution is used to measure
     * the CPU execution time jitter. Any change to the loop in this function
     * implies that careful retesting must be done.
     *
     * @param rd - entropy collector struct -- may be NULL
     * @param time - time stamp to be injected
     *
     * Output:
     * updated rd.data
     *
     * @return Number of loops the folding operation is performed
     */    
    private long lfsrTime(RandomData rd, long time) {
        int i;
        long j = 0;
        long n = 0;
        long fold_loop_cnt = loopShuffle(rd, MAX_FOLD_LOOP_BIT, MIN_FOLD_LOOP_BIT);

        for (j = 0; j < fold_loop_cnt; j++) {
            n = rd.data;
            for (i = 1; (DATA_SIZE_BITS) >= i; i++) {
                long tmp = time << (DATA_SIZE_BITS - i);

                tmp = tmp >>> (DATA_SIZE_BITS - 1);
                
                /*
                 * Fibonacci LSFR with polynomial of x^64 + x^61 + x^56 + x^31 +
                 * x^28 + x^23 + 1 which is primitive according to
                 * http://poincare.matf.bg.ac.rs/~ezivkovm/publications/primpol1
                 * .pdf (the shift values are the polynomial values minus one
                 * due to counting bits from 0 to 63). As the current position
                 * is always the LSB, the polynomial only needs to shift data in
                 * from the left without wrap.
                 */
                n ^= ((n >>> 63) & 1);
                n ^= ((n >>> 60) & 1);
                n ^= ((n >>> 55) & 1);
                n ^= ((n >>> 30) & 1);
                n ^= ((n >>> 27) & 1);
                n ^= ((n >>> 22) & 1);
                n <<= 1;
                n ^= tmp;
            }
        }
        rd.data = n;

        return fold_loop_cnt;
    }

    private long rol64(long word, int shift) {
        return (word << shift) | (word >>> (64 - shift));
    }

    /**
     * Memory Access noise source -- this is a noise source based on variations in
     *               memory access times
     *
     * This function performs memory accesses which will add to the timing
     * variations due to an unknown amount of CPU wait states that need to be
     * added when accessing memory. The memory size should be larger than the L1
     * caches as outlined in the documentation and the associated testing.
     *
     * The L1 cache has a very high bandwidth, albeit its access rate is  usually
     * slower than accessing CPU registers. Therefore, L1 accesses only add minimal
     * variations as the CPU has hardly to wait. Starting with L2, significant
     * variations are added because L2 typically does not belong to the CPU any more
     * and therefore a wider range of CPU wait states is necessary for accesses.
     * L3 and real memory accesses have even a wider range of wait states. However,
     * to reliably access either L3 or memory, the ec->mem memory must be quite
     * large which is usually not desirable.
     *
     * Input:
     * @ec Reference to the entropy collector with the memory access data -- if
     *     the reference to the memory block to be accessed is NULL, this noise
     *     source is disabled
     * @loop_cnt if a value not equal to 0 is set, use the given value as number of
     *       loops to perform the folding
     *
     * @return Number of memory access operations
     */    
    protected long memAccess(RandomData rd) {
        long i = 0;
        long acc_loop_cnt = loopShuffle(rd, MAX_ACC_LOOP_BIT, MIN_ACC_LOOP_BIT);

        int wrap = rd.memblocksize * rd.memblocks;

        for (i = 0; i < rd.memaccessloops + acc_loop_cnt; i++) {
            int b = toUnsignedInt(rd.mem[rd.memlocation]);
            /*
             * memory access: just add 1 to one byte, wrap at 255 -- memory
             * access implies read from and write to memory location
             */
            rd.mem[rd.memlocation] = (byte) ((b + 1) & 0xff);
            /*
             * Addition of memblocksize - 1 to pointer with wrap around logic to
             * ensure that every memory location is hit evenly
             */
            rd.memlocation = rd.memlocation + rd.memblocksize - 1;
            rd.memlocation = rd.memlocation % wrap;
        }
        return i;
    }

    public static int toUnsignedInt(byte x) {
        return ((int) x) & 0xff;
    }

    /**
     * Update of the loop count used for the next round of
     * an entropy collection.
     *
     * Input:
     * @param rd entropy collector struct -- may be NULL
     * @param bits is the number of low bits of the timer to consider
     * @param min is the number of bits we shift the timer value to the right at
     *  the end to make sure we have a guaranteed minimum value
     *
     * @return Newly calculated loop counter
     */    
    protected long loopShuffle(RandomData rd, int bits, int min) {
        long time = 0;
        long shuffle = 0;
        int i = 0;
        int mask = (1 << bits) - 1;

        time = System.nanoTime();
        /*
         * Mix the current state of the random number into the shuffle
         * calculation to balance that shuffle a bit more.
         */
        if (rd != null)
            time ^= rd.data;
        /*
         * We fold the time value as much as possible to ensure that as many
         * bits of the time stamp are included as possible.
         */
        for (i = 0; ((DATA_SIZE_BITS + bits - 1) / bits) > i; i++) {
            shuffle ^= time & mask;
            time = time >>> bits;
        }

        /*
         * We add a lower boundary value to ensure we have a minimum RNG loop
         * count.
         */
        return (shuffle + (1 << min));
    }

}
