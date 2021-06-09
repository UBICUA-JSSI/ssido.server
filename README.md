# SSIDO.Server

The SSIDO server is implemented using a modified version of the [Yubico WebAuthn server](https://developers.yubico.com/java-webauthn-server/).

The SSIDO server architecture contains the following components:
- DID Resolver web application

## DID Resolver

**Prerequisites**:
-	[Open JDK 15+](https://openjdk.java.net/)
-	[Apache Netbeans 12+](https://netbeans.apache.org/)
-	[Wildfly 21+](https://www.wildfly.org/)

**Configuration**:
The application directory must be configured in the resolver.web file placed in <project>/resolver/resolver.web/src/main/webapp/WEB-INF/web.xml.

in the context-param property:

```
<context-param>
     <param-name>jssi.driver.config</param-name>
     <param-value><project>/resolver/resolver.assets/config.json</param-value>
</context-param>
```

The config.json file contains the necessary configurations for all the drivers included in the deployable resolver.ear file. Due to the fact that the identity DLT is currently [Hyperledger Indy](), the relevant configuration is named driver.sov. Its configuration is located at the same we.xml file:

 ```
 <context-param>
      <param-name>jssi.driver.config</param-name>
      <param-value><project>/resolver/resolver.assets/driver.properties</param-value>
 </context-param>
```
 
As an example, the driver.properties contains the following:
 ```
### Array of genesis ###
resolver.config=ubicua/project/resolver/resolver.assets/ubicua.genesis

### Libindy path ###
resolver.native=<project>/hyperledger.native

### Resolver wallet ###
wallet.resolver.id=resolver_wallet
wallet.resolver.key=resolver_wallet_key
 ```
By default, the Resolver DID has the assigned value of V4SGRU86Z58d6TV7PBUe6f. It means that the Resolver Wallet contains the necessary cryptographic material to sign their requests to the Ubicua DLT. Before testing, it is necessary to check that the Wallet has been created and the Resolver DID has been registered. This operation is described in the jssi.wallet module.

**Logging**:

 To enable the logging service, open the Widfly configuration file, i.e. directory/standalone/configuration/standalone-full.xml, and modify the profile/subsystem xmlns="urn:jboss:domain:logging:8.0" property as follows:
 
 ```
<logger category="jssi">
     <level name="DEBUG"/>
 </logger>
 ```
 
**Execution**:
 
It is required to compile, package and deploy the resolver.ear application on the Wildfly server. To test the application, open a browser with the link:
http://localhost:8080/resolver/1.0/identifiers/did:sov:ubicua:V4SGRU86Z58d6TV7PBUe6f
 






