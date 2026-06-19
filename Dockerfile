FROM eclipse-temurin:21-jre-jammy

WORKDIR /app
ARG JAR_FILE=target/auth-gateway-*.jar
COPY ${JAR_FILE} /app/auth-gateway.jar

EXPOSE 8090

ENTRYPOINT ["java", "-jar", "/app/auth-gateway.jar"]
