## How to use Continent file container with compressed one-time pad

One-time pad derived from Skein PRNG. Skein PRNG continuously seeded with 64-bit values derived from Hardware RNG. Depending on CPU load and speed, new seed value can be applied approximatly every 5 milliseconds. Therefore overall key data could be about 2+ million bits per 1Gb of encrypted data.
In compressed format one-time pad contains: series of seeded value and number of bytes (total bytes / 512 bytes buffer) produced by Skein PRNG since the moment when seed was applied.

#### Show usage help

java -jar continent.jar container

#### Encrypt files

java -jar continent.jar container e -otpm1 -otpcZ:\key.dat Z:\container.dat Z:\my-files

#### Decrypt files

java -jar continent.jar container d -otpcZ:\key.dat -oZ:\my-files Z:\container.dat