FROM eclipse-temurin:21-jre-jammy

WORKDIR /app
ARG JAR_FILE=target/auth-gateway-*.jar
COPY ${JAR_FILE} /app/auth-gateway.jar

EXPOSE 8090

ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd --system --gid "${APP_GID}" authgateway \
    && useradd --system --uid "${APP_UID}" --gid authgateway --home-dir /app --shell /usr/sbin/nologin authgateway \
    && mkdir -p /app/logs \
    && chown -R authgateway:authgateway /app
USER 10001:10001

ENTRYPOINT ["java", "-jar", "/app/auth-gateway.jar"]
