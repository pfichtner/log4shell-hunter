# log4shell-hunter

[![Java CI with Maven](https://github.com/pfichtner/log4shell-hunter/actions/workflows/maven.yml/badge.svg)](https://github.com/pfichtner/log4shell-hunter/actions/workflows/maven.yml)
[![GitLicense](https://gitlicense.com/badge/pfichtner/log4shell-hunter)](https://gitlicense.com/license/pfichtner/log4shell-hunter)
[![Known Vulnerabilities](https://snyk.io/test/github/pfichtner/log4shell-hunter/badge.svg?targetFile=pom.xml)](https://snyk.io/test/github/pfichtner/log4shell-hunter?targetFile=pom.xml)
[![BCH compliance](https://bettercodehub.com/edge/badge/pfichtner/log4shell-hunter?branch=main)](https://bettercodehub.com/)

Are you afraid of having JARs where a vulnerable version of log4j was included (shaded) or that coders did copy vulnerable log4j classes into the project. This is where most scanners will have false negatives because they rely on metadata like pom.xml describing the log4j version. 

This scanner does bytecode analysis! So it does **not** depend on: 
- fingerprinted jar files
- fingerprinted class files
- class names (e.g. ```JndiLookup```)
- poms/pom entries

So log4shell-hunter will find vulnerable log4j versions even if: 
- log4j's source has been compiled by third-parties (no matter what compiler/compiler version)
- log4j (or parts of it) has/have been included/copied in/to other jars
- log4j was repacked (uberjar, fatjar), even if packages have been renamed, e.g. org.apache.logging -> org.acme.foo.logger.bar

The scanner analyzes jars and tries to detect: 
- classes that are annotated with log4j's Plugin annotation ```org.apache.logging.log4j.core.config.plugins.Plugin```. 
- This even works if the Plugin has renamed or even obfuscated (depending on the log4shell-hunter's mode parameter)

### Usage
Example usage
```
find \( -name "*.jar" -o -name "*.zip" -o -name "*.ear" -o -name "*.war" \) -exec java -jar log4shell-hunter-0.0.2.jar -m obfuscatorComparator {} \;
```

Example output
```
./log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.war
> Possible 2.1+ match found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /WEB-INF/lib/log4j-core-2.10.0.jar
```

Mode can be se to one of ```defaultComparator```, ```repackageComparator```, ```obfuscatorComparator```. 
- defaultComparator: Log4j classes have to match exactly the expected class+package name. Same apply for their methods. 
- repackageComparator: Log4j classes have to match the expected names where package name will be ignored. Method names have to match exactly (**default**)
- obfuscatorComparator: log4shell-hunter does not depend on any class or method names but tries to detect log4 classes by some criteria. This mode will find even repackaged log4js even if the jar has been obfuscated

### Build from source
```
git clone https://github.com/pfichtner/log4shell-hunter.git
cd log4shell-hunter/
./mvnw package # of course you can use your locally installed "mvn" instead of the maven wrapper "./mvnw"
java -jar target/log4shell-hunter-0.0.2.jar
```

### License
[GNU General Public License v3.0](LICENSE.txt)
