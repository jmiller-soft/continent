//#include <android/log.h>
#include <jni.h>

/*
 * Non-physical true random number generator based on timing jitter.
 *
 * Copyright Stephan Mueller <smueller@chronox.de>, 2014 - 2018
 *
 * Design
 * ======
 *
 * See documentation in doc/ folder.
 *
 * Interface
 * =========
 *
 * See documentation in doc/ folder.
 *
 * License
 * =======
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the GPL2 are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#undef _FORTIFY_SOURCE
#pragma GCC optimize ("O0")

#include "jitterentropy.h"

#ifndef CONFIG_CRYPTO_CPU_JITTERENTROPY_STAT
/* only check optimization in a compilation for real work */
#ifdef __OPTIMIZE__
#error "The CPU Jitter random number generator must not be compiled with optimizations. See documentation. Use the compiler switch -O0 for compiling jitterentropy-base.c."
#endif
#endif

#define MAJVERSION 2 /* API / ABI incompatible changes, functional changes that
		      * require consumer to be updated (as long as this number
		      * is zero, the API is not considered stable and can
		      * change without a bump of the major version) */
#define MINVERSION 1 /* API compatible, ABI may change, functional
		      * enhancements only, consumer can be left unchanged if
		      * enhancements are not considered */
#define PATCHLEVEL 2 /* API / ABI compatible, no functional changes, no
		      * enhancements, bug fixes only */

/**
 * jent_version() - Return machine-usable version number of jent library
 *
 * The function returns a version number that is monotonic increasing
 * for newer versions. The version numbers are multiples of 100. For example,
 * version 1.2.3 is converted to 1020300 -- the last two digits are reserved
 * for future use.
 *
 * The result of this function can be used in comparing the version number
 * in a calling program if version-specific calls need to be make.
 *
 * Return: Version number of jitterentropy library
 */
JENT_PRIVATE_STATIC
unsigned int jent_version(void)
{
    unsigned int version = 0;

    version =  MAJVERSION * 1000000;
    version += MINVERSION * 10000;
    version += PATCHLEVEL * 100;

    return version;
}

/**
 * Update of the loop count used for the next round of
 * an entropy collection.
 *
 * Input:
 * @ec entropy collector struct -- may be NULL
 * @bits is the number of low bits of the timer to consider
 * @min is the number of bits we shift the timer value to the right at
 * 	the end to make sure we have a guaranteed minimum value
 *
 * @return Newly calculated loop counter
 */
static uint64_t jent_loop_shuffle(struct rand_data *ec,
                                  unsigned int bits, unsigned int min)
{
    uint64_t time = 0;
    uint64_t shuffle = 0;
    unsigned int i = 0;
    unsigned int mask = (1<<bits) - 1;

    jent_get_nstime(&time);
    /*
     * Mix the current state of the random number into the shuffle
     * calculation to balance that shuffle a bit more.
     */
    if (ec)
        time ^= ec->data;
    /*
     * We fold the time value as much as possible to ensure that as many
     * bits of the time stamp are included as possible.
     */
    for (i = 0; ((DATA_SIZE_BITS + bits - 1) / bits) > i; i++) {
        shuffle ^= time & mask;
        time = time >> bits;
    }

    /*
     * We add a lower boundary value to ensure we have a minimum
     * RNG loop count.
     */
    return (shuffle + (1<<min));
}

/***************************************************************************
 * Noise sources
 ***************************************************************************/

/**
 * CPU Jitter noise source -- this is the noise source based on the CPU
 * 			      execution time jitter
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
 * Input:
 * @ec entropy collector struct -- may be NULL
 * @time time stamp to be injected
 * @loop_cnt if a value not equal to 0 is set, use the given value as number of
 *	     loops to perform the folding
 *
 * Output:
 * updated ec->data
 *
 * @return Number of loops the folding operation is performed
 */
static uint64_t jent_lfsr_time(struct rand_data *ec, uint64_t time,
                               uint64_t loop_cnt)
{
    unsigned int i;
    uint64_t j = 0;
    uint64_t new1 = 0;
#define MAX_FOLD_LOOP_BIT 4
#define MIN_FOLD_LOOP_BIT 0
    uint64_t fold_loop_cnt =
            jent_loop_shuffle(ec, MAX_FOLD_LOOP_BIT, MIN_FOLD_LOOP_BIT);

    /*
     * testing purposes -- allow test app to set the counter, not
     * needed during runtime
     */
    if (loop_cnt)
        fold_loop_cnt = loop_cnt;
    for (j = 0; j < fold_loop_cnt; j++) {
        new1 = ec->data;
        for (i = 1; (DATA_SIZE_BITS) >= i; i++) {
            uint64_t tmp = time << (DATA_SIZE_BITS - i);

            tmp = tmp >> (DATA_SIZE_BITS - 1);

            /*
            * Fibonacci LSFR with polynomial of
            *  x^64 + x^61 + x^56 + x^31 + x^28 + x^23 + 1 which is
            *  primitive according to
            *   http://poincare.matf.bg.ac.rs/~ezivkovm/publications/primpol1.pdf
            * (the shift values are the polynomial values minus one
            * due to counting bits from 0 to 63). As the current
            * position is always the LSB, the polynomial only needs
            * to shift data in from the left without wrap.
            */
            tmp ^= ((new1 >> 63) & 1);
            tmp ^= ((new1 >> 60) & 1);
            tmp ^= ((new1 >> 55) & 1);
            tmp ^= ((new1 >> 30) & 1);
            tmp ^= ((new1 >> 27) & 1);
            tmp ^= ((new1 >> 22) & 1);
            new1 <<= 1;
            new1 ^= tmp;
        }
    }
    ec->data = new1;

    return fold_loop_cnt;
}

/**
 * Memory Access noise source -- this is a noise source based on variations in
 * 				 memory access times
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
 *	     loops to perform the folding
 *
 * @return Number of memory access operations
 */
static unsigned int jent_memaccess(struct rand_data *ec, uint64_t loop_cnt)
{
    unsigned int wrap = 0;
    uint64_t i = 0;
#define MAX_ACC_LOOP_BIT 7
#define MIN_ACC_LOOP_BIT 0
    uint64_t acc_loop_cnt =
            jent_loop_shuffle(ec, MAX_ACC_LOOP_BIT, MIN_ACC_LOOP_BIT);

    if (NULL == ec || NULL == ec->mem)
        return 0;
    wrap = ec->memblocksize * ec->memblocks;

    /*
     * testing purposes -- allow test app to set the counter, not
     * needed during runtime
     */
    if (loop_cnt)
        acc_loop_cnt = loop_cnt;

    for (i = 0; i < (ec->memaccessloops + acc_loop_cnt); i++) {
        unsigned char *tmpval = ec->mem + ec->memlocation;
        /*
         * memory access: just add 1 to one byte,
         * wrap at 255 -- memory access implies read
         * from and write to memory location
         */
        *tmpval = (*tmpval + 1) & 0xff;
        /*
         * Addition of memblocksize - 1 to pointer
         * with wrap around logic to ensure that every
         * memory location is hit evenly
         */
        ec->memlocation = ec->memlocation + ec->memblocksize - 1;
        ec->memlocation = ec->memlocation % wrap;
    }
    return i;
}

/***************************************************************************
 * Start of entropy processing logic
 ***************************************************************************/

/**
 * Stuck test by checking the:
 * 	1st derivation of the jitter measurement (time delta)
 * 	2nd derivation of the jitter measurement (delta of time deltas)
 * 	3rd derivation of the jitter measurement (delta of delta of time deltas)
 *
 * All values must always be non-zero.
 *
 * Input:
 * @ec Reference to entropy collector
 * @current_delta Jitter time delta
 *
 * @return
 * 	0 jitter measurement not stuck (good bit)
 * 	1 jitter measurement stuck (reject bit)
 */
static int jent_stuck(struct rand_data *ec, uint64_t current_delta)
{
    int64_t delta2 = ec->last_delta - current_delta;
    int64_t delta3 = delta2 - ec->last_delta2;

    ec->last_delta = current_delta;
    ec->last_delta2 = delta2;

    if (!current_delta || !delta2 || !delta3)
        return 1;

    return 0;
}

/**
 * This is the heart of the entropy generation: calculate time deltas and
 * use the CPU jitter in the time deltas. The jitter is injected into the
 * entropy pool.
 *
 * WARNING: ensure that ->prev_time is primed before using the output
 * 	    of this function! This can be done by calling this function
 * 	    and not using its result.
 *
 * Input:
 * @entropy_collector Reference to entropy collector
 *
 * @return: result of stuck test
 */
static int jent_measure_jitter(struct rand_data *ec)
{
    uint64_t time = 0;
    uint64_t current_delta = 0;

    /* Invoke one noise source before time measurement to add variations */
    jent_memaccess(ec, 0);

    /*
     * Get time stamp and calculate time delta to previous
     * invocation to measure the timing variations
     */
    jent_get_nstime(&time);
    current_delta = time - ec->prev_time;
//    __android_log_print(ANDROID_LOG_DEBUG, "LOG_TAG", "current_delta %d", (int)current_delta);
    ec->prev_time = time;

    /* Now call the next noise sources which also injects the data */
    jent_lfsr_time(ec, current_delta, 0);

    /* Check whether we have a stuck measurement. */
    return jent_stuck(ec, current_delta);
}

/**
 * Generator of one 64 bit random number
 * Function fills rand_data->data
 *
 * Input:
 * @ec Reference to entropy collector
 */
static void jent_gen_entropy(struct rand_data *ec)
{
    unsigned int k = 0;

    /* priming of the ->prev_time value */
    jent_measure_jitter(ec);

    while (1) {
        /* If a stuck measurement is received, repeat measurement */
        if (jent_measure_jitter(ec))
            continue;

        /*
         * We multiply the loop value with ->osr to obtain the
         * oversampling rate requested by the caller
         */
        if (++k >= (DATA_SIZE_BITS * ec->osr))
            break;
    }
}

/**
 * The continuous test required by FIPS 140-2 -- the function automatically
 * primes the test if needed.
 *
 * Return:
 * 0 if FIPS test passed
 * < 0 if FIPS test failed
 */
static int jent_fips_test(struct rand_data *ec)
{
    if (ec->fips_enabled == -1)
        return 0;

    if (ec->fips_enabled == 0) {
        if (!jent_fips_enabled()) {
            ec->fips_enabled = -1;
            return 0;
        } else
            ec->fips_enabled = 1;
    }

    /* prime the FIPS test */
    if (!ec->old_data) {
        ec->old_data = ec->data;
        jent_gen_entropy(ec);
    }

    if (ec->data == ec->old_data)
        return -1;

    ec->old_data = ec->data;

    return 0;
}

/**
 * Entry function: Obtain entropy for the caller.
 *
 * This function invokes the entropy gathering logic as often to generate
 * as many bytes as requested by the caller. The entropy gathering logic
 * creates 64 bit per invocation.
 *
 * This function truncates the last 64 bit entropy value output to the exact
 * size specified by the caller.
 *
 * Input:
 * @ec Reference to entropy collector
 * @data pointer to buffer for storing random data -- buffer must already
 *        exist
 * @len size of the buffer, specifying also the requested number of random
 *       in bytes
 *
 * @return number of bytes returned when request is fulfilled or an error
 *
 * The following error codes can occur:
 *	-1	entropy_collector is NULL
 *	-2	FIPS test failed
 */
JENT_PRIVATE_STATIC
        ssize_t jent_read_entropy(struct rand_data *ec, char *data, size_t len)
{
    char *p = data;
    size_t orig_len = len;

    if (NULL == ec)
        return -1;

    while (0 < len) {
        size_t tocopy;

        jent_gen_entropy(ec);
        if (jent_fips_test(ec))
            return -2;

        if ((DATA_SIZE_BITS / 8) < len)
            tocopy = (DATA_SIZE_BITS / 8);
        else
            tocopy = len;
        memcpy(p, &ec->data, tocopy);

        len -= tocopy;
        p += tocopy;
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
#ifndef CONFIG_CRYPTO_CPU_JITTERENTROPY_SECURE_MEMORY
    jent_gen_entropy(ec);
#endif
    return orig_len;
}

/***************************************************************************
 * Initialization logic
 ***************************************************************************/

JENT_PRIVATE_STATIC
struct rand_data *jent_entropy_collector_alloc(unsigned int osr,
                                               unsigned int flags)
{
    struct rand_data *entropy_collector;

    entropy_collector = static_cast<rand_data *>(jent_zalloc(sizeof(struct rand_data)));
    if (NULL == entropy_collector)
        return NULL;

    if (!(flags & JENT_DISABLE_MEMORY_ACCESS)) {
        /* Allocate memory for adding variations based on memory
         * access
         */
        entropy_collector->mem =
                (unsigned char *)jent_zalloc(JENT_MEMORY_SIZE);
        if (NULL == entropy_collector->mem) {
            jent_zfree(entropy_collector, sizeof(struct rand_data));
            return NULL;
        }
        entropy_collector->memblocksize = JENT_MEMORY_BLOCKSIZE;
        entropy_collector->memblocks = JENT_MEMORY_BLOCKS;
        entropy_collector->memaccessloops = JENT_MEMORY_ACCESSLOOPS;
    }

    /* verify and set the oversampling rate */
    if (0 == osr)
        osr = 1; /* minimum sampling rate is 1 */
    entropy_collector->osr = osr;

    entropy_collector->stir = 1;
    if (flags & JENT_DISABLE_STIR)
        entropy_collector->stir = 0;
    if (flags & JENT_DISABLE_UNBIAS)
        entropy_collector->disable_unbias = 1;

    /* fill the data pad with non-zero values */
    jent_gen_entropy(entropy_collector);

    return entropy_collector;
}


JENT_PRIVATE_STATIC
void jent_entropy_collector_free(struct rand_data *entropy_collector)
{
    if (NULL != entropy_collector) {
        if (NULL != entropy_collector->mem) {
            jent_zfree(entropy_collector->mem, JENT_MEMORY_SIZE);
            entropy_collector->mem = NULL;
        }
        jent_zfree(entropy_collector, sizeof(struct rand_data));
    }
}

JENT_PRIVATE_STATIC
int jent_entropy_init(void)
{
    int i;
    uint64_t delta_sum = 0;
    uint64_t old_delta = 0;
    int time_backwards = 0;
    int count_mod = 0;
    int count_stuck = 0;
    struct rand_data ec;

    memset(&ec, 0, sizeof(ec));

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
#define TESTLOOPCOUNT 300
#define CLEARCACHE 100
    for (i = 0; (TESTLOOPCOUNT + CLEARCACHE) > i; i++) {
        uint64_t time = 0;
        uint64_t time2 = 0;
        uint64_t delta = 0;
        unsigned int lowdelta = 0;
        int stuck;

        /* Invoke core entropy collection logic */
        jent_get_nstime(&time);
        ec.prev_time = time;
        jent_lfsr_time(&ec, time, 0);
        jent_get_nstime(&time2);

        /* test whether timer works */
        if (!time || !time2)
            return ENOTIME;
        delta = time2 - time;
        /*
         * test whether timer is fine grained enough to provide
         * delta even when called shortly after each other -- this
         * implies that we also have a high resolution timer
         */
        if (!delta)
            return ECOARSETIME;

        stuck = jent_stuck(&ec, delta);

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
        if (!(lowdelta % 100))
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
        return ENOMONOTONIC;

    /*
     * Variations of deltas of time must on average be larger
     * than 1 to ensure the entropy estimation
     * implied with 1 is preserved
     */
    if ((delta_sum) <= 1)
        return EMINVARVAR;

    /*
     * Ensure that we have variations in the time stamp below 10 for at least
     * 10% of all checks -- on some platforms, the counter increments in
     * multiples of 100, but not always
     */
    if ((TESTLOOPCOUNT/10 * 9) < count_mod)
        return ECOARSETIME;

    /*
     * If we have more than 90% stuck results, then this Jitter RNG is
     * likely to not work well.
     */
    if (JENT_STUCK_INIT_THRES(TESTLOOPCOUNT) < count_stuck)
        return ESTUCK;

    return 0;
}

/***************************************************************************
 * Statistical test logic not compiled for regular operation
 ***************************************************************************/

#ifdef CONFIG_CRYPTO_CPU_JITTERENTROPY_STAT
/*
 * Statistical test: return the time duration for the folding operation. If min
 * is set, perform the given number of LFSR ops. Otherwise, allow the
 * loop count shuffling to define the number of LFSR ops.
 */
JENT_PRIVATE_STATIC
uint64_t jent_lfsr_var_stat(struct rand_data *ec, unsigned int min)
{
	uint64_t time = 0;
	uint64_t time2 = 0;

	jent_get_nstime(&time);
	jent_memaccess(ec, min);
	jent_lfsr_time(ec, time, min);
	jent_get_nstime(&time2);
	return ((time2 - time));
}
#endif /* CONFIG_CRYPTO_CPU_JITTERENTROPY_STAT */

extern "C" {
    JNIEXPORT jint JNICALL
    Java_com_continent_random_entropy_NativeJitterEntropy_initRandom(JNIEnv *env,
                                                           jobject obj) {
        return (jint)jent_entropy_init();
    }

    JNIEXPORT void JNICALL
    Java_com_continent_random_entropy_NativeJitterEntropy_generateRandom(
            JNIEnv *env,
            jobject obj,
            jobject request,
            jobject response) {
        jclass queueClass = env->FindClass("java/util/concurrent/BlockingQueue");
        jclass integerClass = env->FindClass("java/lang/Integer");

        jmethodID addResponse = env->GetMethodID(queueClass, "add", "(Ljava/lang/Object;)Z" );
        jmethodID getRequest = env->GetMethodID(queueClass, "take", "()Ljava/lang/Object;" );
        jmethodID intValue = env->GetMethodID(integerClass, "intValue", "()I" );

        rand_data *s = jent_entropy_collector_alloc(1, 0);
        while (true) {
            jobject sizeObj = env->CallObjectMethod(request, getRequest);
            int size = env->CallIntMethod(sizeObj, intValue);
            if (size < 0) {
                break;
            }

            char buf[size];
            jent_read_entropy(s, buf, size);

            jbyteArray result = env->NewByteArray(size);
            env->SetByteArrayRegion(result, 0, size, (jbyte*)buf);
            env->CallBooleanMethod(response, addResponse, result);
            env->DeleteLocalRef(result);
            env->DeleteLocalRef(sizeObj);

            memset(buf, 0, sizeof buf);
        }
        jent_entropy_collector_free(s);
    }

}