# SSIDO Server

The SSIDO server is a server-side web application developed on the basis of the [Yubico WebAuthn server](https://developers.yubico.com/java-webauthn-server/).

## Prerequisites
- Open JDK 15+
- Apache Netbeans 12+
- Wildfly 21+

## Dependencies
- [JSSI Resolver Server](https://github.com/UBICUA-JSSI/jssi.resolver)
- [JSSI Registrar Server (optionally)](https://github.com/UBICUA-JSSI/jssi.registrar)

## Configuration
The ssido.web coniguration directory is specified in <install_dir>/ssido.server/ssido.web/src/main/resources/ssido.properties.
URLs of JSSI Resolver Server and their properties are set as follows:
```
resolver.uri=http://localhost:8080/resolver/1.0/identifiers
properties.uri=http://localhost:8080/resolver/1.0/properties
```
## Logging
To enable the logging funcionality in Wildfly, open the <install_dir>/standalone/configuration/standalone-full.xml file and modify the
profile/subsystem xmlns="urn:jboss:domain:logging:8.0" section to add the following:
```
<logger category="sssi">
 	<level name="DEBUG"/>
 </logger>
```

In the <install_dir>/ssido.server/ssido.web/src/main/resources/logback.xml file, set the ssido.log path to as follows:
```
<appender name="FILE" class="ch.qos.logback.core.FileAppender">
    <file><your_log_directory>/ssido.log</file>
    <encoder>
        <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
    </encoder>
</appender>
```
## About
![logo](https://github.com/UBICUA-JSSI/ssido.client/blob/main/logo-ngi-essiflab.png) Done within the frame of the NGI eSSIF-Lab Project with financial support from the European Commission Horizon 2020 Programme (Grant Agreement N 871932).



 






