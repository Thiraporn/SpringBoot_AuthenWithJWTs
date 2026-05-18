FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y maven

RUN mkdir -p /root/.m2
RUN cp .m2/settings.xml /root/.m2/settings.xml

RUN mvn clean package -DskipTests

EXPOSE 8080

CMD ["java","-jar","target/authentication-0.0.1-SNAPSHOT.jar"]