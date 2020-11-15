## How to use Continent file container with public and private keys

#### Show usage help

java -jar continent.jar container

#### Generate keys

java -jar continent.jar container g -pbkZ:\public4.key -pvkZ:\private4.key

#### Encrypt files

java -jar continent.jar container e -cfk -pbkZ:\public.key Z:\container.dat Z:\my-files

#### Decrypt files

java -jar continent.jar container d -pbkZ:\public.key -pvkZ:\private.key -oZ:\my-files Z:\container.dat
