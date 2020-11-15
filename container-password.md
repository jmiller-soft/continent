## How to use Continent file container with password

#### Show usage help

java -jar continent.jar container

#### Encrypt files

java -jar continent.jar container e -d1 -cfk -p Z:\container.dat Z:\my-files

#### Decrypt files

java -jar continent.jar container d -d1 -p -oZ:\my-files Z:\container.dat