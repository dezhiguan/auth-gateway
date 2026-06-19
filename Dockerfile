FROM eclipse-temurin:21-jre-jammy

WORKDIR /app
ARG JAR_FILE=target/auth-gateway-*.jar
COPY ${JAR_FILE} /app/auth-gateway.jar

EXPOSE 8090

RUN groupadd --system authgateway && useradd --system --gid authgateway authgateway
USER authgateway

ENTRYPOINT ["java", "-jar", "/app/auth-gateway.jar"]
