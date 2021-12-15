# log4shell-scanner

### WORK IN PROGRESS, RELEASE AVAILABLE SOON

Scans jars and does bytecode analysis. So it does not depend on: 
- fingerprinted jar files
- fingerprinted class files
- class names (e.g. ```JndiLookup```)
- poms/pom entries

So log4shell-scanner will find vulnerable log4j versions even if: 
- log4j's source has was compiled by third-parties (no matter what compiler/compiler version)
- log4j (or parts of it) has/have been included/copied in/to other jars
- log4j was repacked (uberjar, fatjar), even if packages have been renamed, e.g. org.apache.logging -> org.acme.logger

The scanner analyzes jars and tries to detect: 
- classes that are annotated with log4js Plugin annotation ```org.apache.logging.log4j.core.config.plugins.Plugin```.   
  TODO: At the moment log4shell-scanner depends on that classname, in one of the next versions log4shell-scanner tries to detect if a class is annotated with ```Plugin``` even if the class was renamed (perhaps even obfuscated)
- classes that have calls to ```"org.apache.logging.log4j.core.net.JndiManager#lookup(String)"```. 
  TODO: At the moment log4shell-scanner depends on that classname/methodname, in one of the next versions log4shell-scanner tries to detect if there is a call to any public synchronized method throwing a NamingException which has references javax.naming.Context

