package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.Detectors.allDetectors;
import static com.github.stefanbirkner.systemlambda.SystemLambda.catchSystemExit;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemErr;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toList;
import static org.approvaltests.Approvals.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.File;
import java.io.IOException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;

import org.approvaltests.core.Options;
import org.approvaltests.core.Options.FileOptions;
import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.Detectors.Multiplexer;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.io.Detector;
import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

class Log4JHunterTest {

	private static final String SEPARATOR = ",";

	Log4jJars log4jJars = Log4jJars.getInstance();

	@Test
	void detectsAndPrintsViaPluginDetection() {
		DetectionCollector collector = new DetectionCollector(new Log4jPluginAnnotation());
		String expected = "@Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup";
		assertAll( //
				() -> assertThat(runCheck(collector, "2.10.0")).contains("/log4j-core-2.10.0.jar: " + expected), //
				() -> assertThat(runCheck(collector, "2.14.1")).contains("/log4j-core-2.14.1.jar: " + expected) //
		);
	}

	@Test
	void detectsAndPrintsViaCheckForCalls() {
		DetectionCollector collector = new DetectionCollector(new JndiManagerLookupCallsFromJndiLookup());
		String expected = "Reference to org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup";
		assertAll( //
				() -> assertThat(runCheck(collector, "2.10.0")).contains("/log4j-core-2.10.0.jar: " + expected), //
				() -> assertThat(runCheck(collector, "2.14.1")).contains("/log4j-core-2.14.1.jar: " + expected));
	}

	@Test
	void nested() throws Exception {
		String zip = "log4j-core-2.0-beta8---log4j-core-2.0-beta9---log4j-core-2.16.0---log4j-core-2.12.2.zip";
		DetectionCollector collector = new DetectionCollector(allDetectors());
		assertThat(runCheck(collector, new File(getClass().getClassLoader().getResource(zip).toURI()))).contains(asList( //
				zip + ": Reference to javax.naming.Context#lookup(java.lang.String) found in class org.apache.logging.log4j.core.net.JndiManager in resource /log4j-core-2.12.2.jar", //
				zip + ": @Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.12.2.jar", //
				zip + ": log4j2.enableJndi access found in class org.apache.logging.log4j.core.net.JndiManager in resource /log4j-core-2.12.2.jar", //
				zip + ": Reference to org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.16.0.jar", //
				zip + ": Reference to javax.naming.directory.DirContext#lookup(java.lang.String) found in class org.apache.logging.log4j.core.net.JndiManager in resource /log4j-core-2.16.0.jar", //
				zip + ": @Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.16.0.jar", //
				zip + ": log4j2.enableJndi access found in class org.apache.logging.log4j.core.net.JndiManager in resource /log4j-core-2.16.0.jar", //
				zip + ": @Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.0-beta9.jar", //
				zip + ": Reference to javax.naming.InitialContext#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.0-beta9.jar" //
		));
	}

	@Test
	void main() throws Exception {
		String zip = "log4j-core-2.0-beta8---log4j-core-2.0-beta9---log4j-core-2.16.0---log4j-core-2.12.2.zip";
		File file = new File(getClass().getClassLoader().getResource(zip).toURI());
		String[] out = tapSystemOut(() -> Log4JHunter.main(file.getAbsolutePath())).split("\n");
		assertThat(out).hasSize(2).satisfies(a -> {
			assertThat(a[0]).endsWith(
					zip + ": Possible 2.15, 2.16 match found in class org.apache.logging.log4j.core.lookup.JndiLookup"
							+ " in resource /log4j-core-2.16.0.jar");
			assertThat(a[1]).endsWith(zip
					+ ": Possible 2.0-beta9, 2.0-rc1 match found in class org.apache.logging.log4j.core.lookup.JndiLookup"
					+ " in resource /log4j-core-2.0-beta9.jar");
		});
	}

	@Test
	void mainNoArgGiven() throws Exception {
		assertThat(verifyIsError()).containsIgnoringCase("no filename");
	}

	@Test
	void mainInvalidMode() throws Exception {
		assertThat(verifyIsError("-m", "XXX")).contains(allAsmTypeComparatorNames());
	}

	private String verifyIsError(String... args) throws Exception {
		return tapSystemErr(() -> assertThat(catchSystemExit(() -> Log4JHunter.main(args))).isNotZero());
	}

	private List<String> allAsmTypeComparatorNames() {
		return EnumSet.allOf(AsmTypeComparator.class).stream().map(AsmTypeComparator::name).collect(toList());
	}

	@Test
	void approveAll() throws IOException {
		Multiplexer multiplexer = allDetectors();
		verify(toBeApproved(new DetectionCollector(multiplexer), multiplexer.getMultiplexed()), options());
	}

	private static Options options() {
		return new FileOptions(new HashMap<>()).withExtension(".csv");
	}

	private String toBeApproved(DetectionCollector collector, List<AbstractDetector> detectors) throws IOException {
		StringBuilder sb = new StringBuilder();
		sb.append(header(collector, detectors)).append("\n");
		for (File file : log4jJars) {
			sb.append(content(collector, detectors, file)).append("\n");
		}
		return sb.toString();
	}

	private String header(DetectionCollector collector, List<AbstractDetector> detectors) {
		StringBuilder sb = new StringBuilder();
		sb.append("File").append(SEPARATOR);
		for (AbstractDetector visitor : detectors) {
			sb.append(visitor.getName()).append(SEPARATOR);
		}
		return sb.toString();
	}

	private String content(DetectionCollector collector, List<AbstractDetector> detectors, File log4jJar)
			throws IOException {
		List<Detection> detections = collector.analyze(log4jJar.getAbsolutePath());
		StringBuilder sb = new StringBuilder();
		sb.append(log4jJar.getAbsoluteFile().getName()).append(SEPARATOR);
		for (AbstractDetector detector : detectors) {
			sb.append(contains(detections, detector) ? "X" : "").append(SEPARATOR);
		}
		return sb.toString();
	}

	private boolean contains(List<Detection> detections, Detector detector) {
		return detections.stream().map(Detection::getDetector).anyMatch(detector::equals);
	}

	private String runCheck(DetectionCollector collector, String version) throws Exception {
		return runCheck(collector, log4jJars.version(version).getAbsoluteFile());
	}

	private String runCheck(DetectionCollector collector, File file) throws Exception {
		return runCheck(new Log4JHunter(collector), file);
	}

	private String runCheck(Log4JHunter log4jHunter, File file) throws Exception {
		return tapSystemOut(() -> log4jHunter.check(file));
	}

}
