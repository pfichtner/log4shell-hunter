package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForLog4jPluginAnnotation;

public class CheckForLog4jPluginAnnotationTest {

	List<String> versionsWithoutPluginAnnotation = asList( //
			"log4j-core-2.0-alpha1.jar", //
			"log4j-core-2.0-alpha2.jar", //

			"log4j-core-2.0-beta1.jar", //
			"log4j-core-2.0-beta2.jar", //
			"log4j-core-2.0-beta3.jar", //
			"log4j-core-2.0-beta4.jar", //
			"log4j-core-2.0-beta5.jar", //
			"log4j-core-2.0-beta6.jar", //
			"log4j-core-2.0-beta7.jar", //
			"log4j-core-2.0-beta8.jar" //
	);

	@Test
	void canDetectPluginClass() throws Exception {
		Log4jJars log4jJars = Log4jJars.getInstance();
		CheckForLog4jPluginAnnotation sut = new CheckForLog4jPluginAnnotation();
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.getLog4jJarsWithout(versionsWithoutPluginAnnotation));
	}

}
