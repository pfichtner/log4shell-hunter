package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.Util.analyse;
import static com.github.pfichtner.log4shell.scanner.util.Util.withDetections;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.util.Log4jJars;
import com.github.pfichtner.log4shell.scanner.visitor.CheckForLog4jPluginAnnotation;

public class CheckForLog4jPluginAnnotationTest {

	Log4jJars log4jJars = Log4jJars.getInstance();

	List<File> versionsWithoutPluginAnnotation = log4jJars.versions( //
			"2.0-alpha1", //
			"2.0-alpha2", //

			"2.0-beta1", //
			"2.0-beta2", //
			"2.0-beta3", //
			"2.0-beta4", //
			"2.0-beta5", //
			"2.0-beta6", //
			"2.0-beta7", //
			"2.0-beta8" //
	);

	@Test
	void canDetectPluginClass() throws Exception {
		CheckForLog4jPluginAnnotation sut = new CheckForLog4jPluginAnnotation();
		assertThat(withDetections(analyse(log4jJars, sut)))
				.containsOnlyKeys(log4jJars.getLog4jJarsWithout(versionsWithoutPluginAnnotation));
	}

}
