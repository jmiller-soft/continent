package com.continent.random;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import com.continent.codec.DataSet;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.junit.Test;

public abstract class BaseRandomTest {

    abstract RandomGenerator createRandom(byte[] seed);
    
    /**
     * Test to ensure that the output from the RNG is broadly as expected.  This will not
     * detect the subtle statistical anomalies that would be picked up by Diehard, but it
     * provides a simple check for major problems with the output.
     */    
    @Test
    public void testDistribution() {
        byte[] seed = new byte[64+1];
        ThreadLocalRandom.current().nextBytes(seed);

        RandomGenerator random = createRandom(seed);
        RandomDelegator rd = new RandomDelegator(random);
        double pi = calculateMonteCarloValueForPi(rd, 100000);
        assertThat(approxEquals(pi, Math.PI, 0.01)).isTrue();
    }
    
    /**
     * Test to ensure that the output from the RNG is broadly as expected.  This will not
     * detect the subtle statistical anomalies that would be picked up by Diehard, but it
     * provides a simple check for major problems with the output.
     */
    @Test
    public void testStandardDeviation()
    {
        byte[] seed = new byte[64+1];
        ThreadLocalRandom.current().nextBytes(seed);
        
        RandomGenerator random = createRandom(seed);
        RandomDelegator rng = new RandomDelegator(random);
        // Expected standard deviation for a uniformly distributed population of values in the range 0..n
        // approaches n/sqrt(12).
        int n = 100;
        double observedSD = calculateSampleStandardDeviation(rng, n, 10000);
        double expectedSD = 100 / Math.sqrt(12);
        assertThat(approxEquals(observedSD, expectedSD, 0.02)).isTrue();
    }

    
    /**
     * This is a rudimentary check to ensure that the output of a given RNG
     * is approximately uniformly distributed.  If the RNG output is not
     * uniformly distributed, this method will return a poor estimate for the
     * value of pi.
     * @param rng The RNG to test.
     * @param iterations The number of random points to generate for use in the
     * calculation.  This value needs to be sufficiently large in order to
     * produce a reasonably accurate result (assuming the RNG is uniform).
     * Less than 10,000 is not particularly useful.  100,000 should be sufficient.
     * @return An approximation of pi generated using the provided RNG.
     */
    public static double calculateMonteCarloValueForPi(Random rng,
                                                       int iterations)
    {
        // Assumes a quadrant of a circle of radius 1, bounded by a box with
        // sides of length 1.  The area of the square is therefore 1 square unit
        // and the area of the quadrant is (pi * r^2) / 4.
        int totalInsideQuadrant = 0;
        // Generate the specified number of random points and count how many fall
        // within the quadrant and how many do not.  We expect the number of points
        // in the quadrant (expressed as a fraction of the total number of points)
        // to be pi/4.  Therefore pi = 4 * ratio.
        for (int i = 0; i < iterations; i++)
        {
            double x = rng.nextDouble();
            double y = rng.nextDouble();
            if (isInQuadrant(x, y))
            {
                ++totalInsideQuadrant;
            }
        }
        // From these figures we can deduce an approximate value for Pi.
        return 4 * ((double) totalInsideQuadrant / iterations);
    }

    /**
     * Uses Pythagoras' theorem to determine whether the specified coordinates
     * fall within the area of the quadrant of a circle of radius 1 that is
     * centered on the origin.
     * @param x The x-coordinate of the point (must be between 0 and 1).
     * @param y The y-coordinate of the point (must be between 0 and 1).
     * @return True if the point is within the quadrant, false otherwise.
     */
    private static boolean isInQuadrant(double x, double y)
    {
        double distance = Math.sqrt((x * x) + (y * y));
        return distance <= 1;
    }

    /**
     * Checks that two values are approximately equal (plus or minus a specified tolerance).
     * @param value1 The first value to compare.
     * @param value2 The second value to compare.
     * @param tolerance How much (in percentage terms, as a percentage of the first value)
     * the values are allowed to differ and still be considered equal.  Expressed as a value
     * between 0 and 1.
     * @return true if the values are approximately equal, false otherwise.
     */
    public static boolean approxEquals(double value1,
                                       double value2,
                                       double tolerance)
    {
        if (tolerance < 0 || tolerance > 1)
        {
            throw new IllegalArgumentException("Tolerance must be between 0 and 1.");
        }
        return Math.abs(value1 - value2) <= value1 * tolerance;
    }
    
    /**
     * Generates a sequence of values from a given random number generator and
     * then calculates the standard deviation of the sample.
     * @param rng The RNG to use.
     * @param maxValue The maximum value for generated integers (values will be
     * in the range [0, maxValue)).
     * @param iterations The number of values to generate and use in the standard
     * deviation calculation.
     * @return The standard deviation of the generated sample.
     */
    public static double calculateSampleStandardDeviation(Random rng,
                                                          int maxValue,
                                                          int iterations)
    {
        DataSet dataSet = new DataSet(iterations);
        for (int i = 0; i < iterations; i++)
        {
            dataSet.addValue(rng.nextInt(maxValue));
        }
        return dataSet.getSampleStandardDeviation();
    }

    
}
