FROM eclipse-temurin:17-jre-jammy

WORKDIR /app
COPY target/auth-gateway-*.jar /app/auth-gateway.jar

EXPOSE 8090

ENTRYPOINT ["java", "-jar", "/app/auth-gateway.jar"]
