# OWASP Benchmark protected at runtime by ByteHide Runtime (Java agent).
#
# Builds the Benchmark web application and serves it on Tomcat with the ByteHide Runtime
# agent attached in block mode. Detected attacks (SQLi, XSS, path traversal, command,
# LDAP and XPath injection) are answered with HTTP 403 (RFC 7807). No application code is
# modified: the agent is attached through the JVM (-javaagent).
#
# Build context is the Benchmark repository root (see docker-compose.yml).
FROM maven:3.9-eclipse-temurin-17

# Tomcat used to run the application. Pre-fetched at build time so container start needs
# no external download.
ARG TOMCAT_VERSION=9.0.115
ARG TOMCAT_URL=https://archive.apache.org/dist/tomcat/tomcat-9/v${TOMCAT_VERSION}/bin/apache-tomcat-${TOMCAT_VERSION}.zip

WORKDIR /benchmark

# ByteHide Runtime: agent, configuration, and the servlet API used by the inbound scan.
COPY bytehide-runtime/packages/monitor-java-agent-1.0.4.jar /opt/bytehide/monitor-java-agent.jar
COPY bytehide-runtime/packages/monitor-config.json          /opt/bytehide/monitor.json
COPY bytehide-runtime/packages/servlet-api.jar              /opt/bytehide/servlet-api.jar

# Application source.
COPY . /benchmark

# Skip quality/format/test plugins for every Maven run: they are irrelevant to producing the
# deployable artifact, and Spotless additionally requires the git repository (not in the image).
# Honored by Maven 3.9+ on both the build steps below and the run command.
ENV MAVEN_ARGS="-Dspotless.check.skip=true -Dspotless.apply.skip=true -Dspotbugs.skip=true -Dpmd.skip=true -Dcpd.skip=true -Denforcer.skip=true -Dmaven.test.skip=true"

# Pre-fetch Tomcat, build the application, and cache dependencies so the first start is fast.
# The database/LDAP backends are started at run time, not during build. Dependency caching is
# best-effort and never fails the build.
RUN set -e; \
    curl -fsSL "${TOMCAT_URL}" -o /opt/bytehide/tomcat.zip; \
    mvn -B -q initialize; \
    mvn -B -q package; \
    mvn -B -q dependency:go-offline -Pdeploy || true

# ByteHide Runtime configuration (read by the agent).
#   BYTEHIDE_MONITOR_CONFIG      protection set and actions (all in block mode)
#   BYTEHIDE_SCAN_CUSTOM_HEADERS also scan application-defined headers (this app delivers
#                               many inputs through a per-test custom header)
ENV BYTEHIDE_MONITOR_CONFIG=/opt/bytehide/monitor.json \
    BYTEHIDE_SCAN_CUSTOM_HEADERS=true \
    BENCH_MAX_HEAP=4g

# HTTPS port inside the container (map a host port in docker-compose.yml).
EXPOSE 9443

# Start the database/LDAP backends, then run Tomcat in the foreground with the agent attached.
# (Remove any database state left from the image build so it starts fresh.)
CMD rm -rf target/db target/log; \
    mvn -B package cargo:run -Pdeploy \
      -Drunenv=docker \
      -Dtomcat.url="file:/opt/bytehide/tomcat.zip" \
      -Dcargo.servlet.port=9443 \
      -Dtomcat.jvmargs="-Xms512m -Xmx${BENCH_MAX_HEAP}" \
      -Dtomcat.jvmargs.debug="-javaagent:/opt/bytehide/monitor-java-agent.jar -Xbootclasspath/a:/opt/bytehide/servlet-api.jar"
