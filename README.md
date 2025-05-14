./mvn spring-boot:run
./mvn clean

# Clean and then compile
./mvn clean compile

# Clean and create a package (JAR/WAR file)
./mvn clean package

# Clean, package, and install to local repository
./mvn clean install


docker build -t riazvm/certkeystore:latest .

docker push riazvm/certkeystore:latest


