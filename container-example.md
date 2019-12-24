## How to use Continent file container

#### Show usage help

java -jar continent.jar container

#### Encrypt files with password

java -XX:CompileCommand=exclude,com/continent/random/entropy/JitterEntropy.* -jar continent.jar container e -d3 -cfk -p container.dmp Z:\my-files

#### Decrypt files with password

java -jar continent.jar container d -d3 -p -oZ:\my-files container.dmp

#### Generate public and private keys

java -XX:CompileCommand=exclude,com/continent/random/entropy/JitterEntropy.* -jar continent.jar container g -pbkZ:\public4.key -pvkZ:\private4.key

#### Encrypt files public key

java -XX:CompileCommand=exclude,com/continent/random/entropy/JitterEntropy.* -jar continent.jar container e -cfk -pbkZ:\public.key container.dmp Z:\my-files

#### Decrypt files with public and private keys

java -jar continent.jar container d -pbkZ:\public.key -pvkZ:\private.key -oZ:\my-files container.dmp
