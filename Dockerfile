FROM eclipse-temurin:17-jdk

ARG GITHUB_USERNAME
ARG GITHUB_TOKEN

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y maven

RUN echo "AUTHEN_COMMONLIBS>>" $GITHUB_USERNAME
RUN test -n "$GITHUB_TOKEN" && echo "TOKEN_EXISTS"

RUN mkdir -p /root/.m2
RUN cp .m2/settings.xml /root/.m2/settings.xml

RUN mvn --settings /root/.m2/settings.xml clean package -DskipTests

EXPOSE 8080

CMD ["java","-jar","target/authentication-0.0.1-SNAPSHOT.jar"]