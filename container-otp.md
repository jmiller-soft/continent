## How to use Continent file container with one-time pad

One-time pad derived from Skein PRNG. Skein PRNG continuously seeded with 64-bit values derived from [Hardware RNG based on CPU timing jitter](http://www.chronox.de/jent.html). New seed value generation time depends on CPU speed. Overall key data could be about 2 million bits per 1Gb of encrypted data. This gives almost perfect secrecy. In non-compressed format one-time pad size coincides with size of container.

#### Show usage help

java -jar continent.jar container

#### Encrypt files using compressed One-time pad

java -jar continent.jar container e -otpm1 -otpcZ:\key.dat Z:\container.dat Z:\my-files

#### Decrypt files using compressed One-time pad

java -jar continent.jar container d -otpcZ:\key.dat -oZ:\my-files Z:\container.dat

#### Encrypt files using non-compressed One-time pad

java -jar continent.jar container e -otpm1 -otpZ:\key.dat Z:\container.dat Z:\my-files

#### Decrypt files using non-compressed One-time pad

java -jar continent.jar container d -otpZ:\key.dat -oZ:\my-files Z:\container.dat
