#!/bin/sh

# downloads all jars from maven-central to log4jars directory

mkdir log4jars/
for v in `cat versions.txt`; do
	wget -c -P log4jars/ https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/$v/log4j-core-$v.jar
done
