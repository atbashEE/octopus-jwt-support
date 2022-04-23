[![License](https://img.shields.io/:license-Apache2-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/be.atbash.json/octopus-jwt-support/badge.svg)](https://maven-badges.herokuapp.com/maven-central/be.atbash.json/octopus-jwt-support)

# octopus-jwt-support
Wrap Java Objects as JWT and Sign or encrypt. Also support JWT tokens.

Support library for Atbash Octopus, Atbash Config Server and others.

Support for Java 11 and Jakarta Namespace

Does have issues on OpenJDK with EC keys (not with Oracle JDK and Azul Zulu)

Since 1.0.0, parts of the **Nimbus JOSE + JWT** (version 8.2) are integrated to have JSONP/JSONB support and allows for an optimized usage.