package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.Detectors.allDetectors;
import static com.github.stefanbirkner.systemlambda.SystemLambda.catchSystemExit;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemErr;
import static com.github.stefanbirkner.systemlambda.SystemLambda.tapSystemOut;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.joining;
import static org.approvaltests.Approvals.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.approvaltests.core.Options;
import org.approvaltests.core.Options.FileOptions;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.DefaultLocale;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.io.Detector;
import com.github.pfichtner.log4shell.scanner.util.Log4jJars;

@DefaultLocale(language = "en")
class Log4ShellHunterTest {

	private static final String STDERR = "STDERR";
	private static final String STDOUT = "STDOUT";
	private static final String RC = "RC";

	private static final String SEPARATOR = ",";

	Log4jJars log4jJars = Log4jJars.getInstance();

	@Test
	void detectsAndPrintsViaPluginDetection() {
		DetectionCollector collector = new DetectionCollector(new Log4jPluginAnnotation());
		String expected = "> @Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup";
		assertAll( //
				() -> assertThat(runCheck(collector, log4jJars.version("2.10.0"))) //
						.contains("/log4j-core-2.10.0.jar") //
						.contains(expected), //
				() -> assertThat(runCheck(collector, log4jJars.version("2.14.1"))) //
						.contains("/log4j-core-2.14.1.jar") //
						.contains(expected) //
		);
	}

	@Test
	void detectsAndPrintsViaCheckForCalls() {
		DetectionCollector collector = new DetectionCollector(new JndiManagerLookupCallsFromJndiLookup());
		String expected = "> Reference to org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup";
		assertAll( //
				() -> assertThat(runCheck(collector, log4jJars.version("2.10.0"))) //
						.contains("/log4j-core-2.10.0.jar") //
						.contains(expected), //
				() -> assertThat(runCheck(collector, log4jJars.version("2.14.1"))) //
						.contains("/log4j-core-2.14.1.jar") //
						.contains(expected) //
		);
	}

	@Test
	void nested() throws Exception {
		File zip = new File(getClass().getClassLoader()
				.getResource("log4j-core-2.0-beta8---log4j-core-2.0-beta9---log4j-core-2.16.0---log4j-core-2.12.2.zip")
				.toURI());
		String[] out = runCheck(new DetectionCollector(new Multiplexer(allDetectors())), zip).split("\n");
		assertThat(out).containsSequence(asList( //
				zip.toString(), //
				"> Reference to javax.naming.Context#lookup(java.lang.String) found in class org.apache.logging.log4j.core.net.JndiManager in resource /log4j-core-2.12.2.jar", //
				"> @Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.12.2.jar", //
				"> log4j2.enableJndi access found in class org.apache.logging.log4j.core.net.JndiManager in resource /log4j-core-2.12.2.jar", //
				"> Reference to org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.16.0.jar", //
				"> Reference to javax.naming.directory.DirContext#lookup(java.lang.String) found in class org.apache.logging.log4j.core.net.JndiManager in resource /log4j-core-2.16.0.jar", //
				"> @Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.16.0.jar", //
				"> log4j2.enableJndi access found in class org.apache.logging.log4j.core.net.JndiManager in resource /log4j-core-2.16.0.jar", //
				"> @Plugin(name = \"jndi\", category = \"Lookup\") found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.0-beta9.jar", //
				"> Reference to javax.naming.InitialContext#lookup(java.lang.String) found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.0-beta9.jar" //
		));
	}

	@Test
	void throwsExceptionIfFileCannotBeRead() throws Exception {
		String zip = "XXXXsomeNonExistentFileXXX.jar";
		RuntimeException rte = assertThrows(RuntimeException.class, () -> new Log4ShellHunter().check(new File(zip)));
		assertThat(rte).hasMessageContaining(zip).hasMessageContaining("not readable");
	}

	@Test
	void main() throws Exception {
		File zip = new File(getClass().getClassLoader()
				.getResource("log4j-core-2.0-beta8---log4j-core-2.0-beta9---log4j-core-2.16.0---log4j-core-2.12.2.zip")
				.toURI());
		String[] out = tapSystemOut(() -> Log4ShellHunter.main(zip.getAbsolutePath())).split("\n");
		assertThat(out).containsSequence(asList( //
				zip.toString(), //
				"> Possible 2.15 <= x <2.17.1 match found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.16.0.jar", //
				"> Possible 2.0-beta9, 2.0-rc1 match found in class org.apache.logging.log4j.core.lookup.JndiLookup in resource /log4j-core-2.0-beta9.jar" //
		));
	}

	@Test
	void mainNoArgGiven() throws Exception {
		verifyMain();
	}

	@Test
	void printsHelp() throws Exception {
		verifyMain("-h");
	}

	@Test
	void mainInvalidMode() throws Exception {
		verifyMain("-m", "XXX-INVALID-MODE-XXX");
	}

	private void verifyMain(String... args) throws Exception {
		verify(execMain(args));
	}

	private String execMain(String... args) throws Exception {
		Map<String, String> values = new HashMap<>();
		values.put(STDERR, tapSystemErr(() -> values.put(STDOUT, tapSystemOut(
				() -> values.put(RC, String.valueOf(catchSystemExit(() -> Log4ShellHunter.main(args))))))));
		return asList( //
				"stdout: " + values.getOrDefault(STDOUT, ""), //
				"stderr: " + values.getOrDefault(STDERR, ""), //
				"rc: " + values.getOrDefault(RC, "") //
		).stream().collect(joining("\n"));
	}

	@Test
	void approveAll() throws IOException {
		Multiplexer multiplexer = new Multiplexer(allDetectors());
		verify(toBeApproved(new DetectionCollector(multiplexer), multiplexer.getMultiplexed()), options());
	}

	@Test
	void approveLog4jDetector() throws IOException {
		Log4JDetector log4jDetector = new Log4JDetector();
		DetectionCollector collector = new DetectionCollector(log4jDetector);
		StringBuilder sb = new StringBuilder();
		for (File file : log4jJars) {
			String detected = collector.analyze(file.getAbsolutePath()).stream().map(Detection::format)
					.collect(joining(SEPARATOR));
			sb.append(file.getAbsoluteFile().getName() + ": " + (detected.isEmpty() ? "-" : detected)).append("\n");
		}
		verify(sb.toString(), options());
	}

	private static Options options() {
		return new FileOptions(new HashMap<>()).withExtension(".csv");
	}

	private String toBeApproved(DetectionCollector collector, Collection<AbstractDetector> detectors) throws IOException {
		StringBuilder sb = new StringBuilder();
		sb.append(header(collector, detectors)).append("\n");
		for (File file : log4jJars) {
			sb.append(content(collector, detectors, file)).append("\n");
		}
		return sb.toString();
	}

	private String header(DetectionCollector collector, Collection<AbstractDetector> detectors) {
		return "File" + SEPARATOR + //
				detectors.stream().map(AbstractDetector::getName).collect(joining(SEPARATOR));
	}

	private String content(DetectionCollector collector, Collection<AbstractDetector> detectors, File jar)
			throws IOException {
		List<Detection> detections = collector.analyze(jar.getAbsolutePath());
		return jar.getAbsoluteFile().getName() + SEPARATOR //
				+ detectors.stream().map(d -> contains(detections, d) ? "X" : "").collect(joining(SEPARATOR));
	}

	private boolean contains(List<Detection> detections, Detector detector) {
		return detections.stream().map(Detection::getDetector).anyMatch(detector::equals);
	}

	private String runCheck(DetectionCollector collector, File file) throws Exception {
		return runCheck(new Log4ShellHunter(collector), file);
	}

	private String runCheck(Log4ShellHunter log4jHunter, File file) throws Exception {
		return tapSystemOut(() -> log4jHunter.check(file));
	}

}
