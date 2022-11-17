#!/bin/bash
mvn clean install -DskipTests
onos-app localhost deactivate nnctu.winlab.proxyarp
onos-app localhost uninstall nctu.winlab.proxyarp
onos-app localhost install! target/ProxyArp-1.0-SNAPSHOT.oar
