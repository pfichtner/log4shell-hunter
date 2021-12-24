# log4shell-hunter

### FIRST RELEASE AVAILABLE

Are you afraid of having JARs where a vulnerable version of log4j was included (shaded) or that coders did copy vulnerable log4j classes into the project. This is where most scanners will have false negatives. Most scanners rely on metadata like pom.xml describing the log4j version. 

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
- 
  This even works if the Plugin has renamed or even obfuscated (depending on the log4shell-hunter's mode parameter)
