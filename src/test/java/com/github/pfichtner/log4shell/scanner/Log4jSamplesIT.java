package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess.LOG4J2_ENABLE_JNDI;
import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static java.nio.file.Files.walk;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detection;
import com.github.pfichtner.log4shell.scanner.Detectors.Multiplexer;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.DirContextLookupsCallsFromJndiManager;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.InitialContextLookupsCalls;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public class Log4jSamplesIT {

	@Test
	void checkMergeBaseSamples() throws IOException {
		// TODO assert if right category (one of following)
		// List<String> asList = Arrays.asList("false-hits", "old-hits", "true-hits");

		CVEDetector sut = new CVEDetector(combined());

		List<String> filenames = filenames("log4j-samples");
		assumeFalse(filenames.isEmpty(), "git submodule empty, please clone recursivly");
		for (String filename : filenames) {
			if (isArchive(filename)) {
				System.out.println("-- " + filename);
				sut.check(filename);
				System.out.println();
			} else {
				// System.err.println("Ignoring " + file);
			}
		}

	}

	@Test
	void checkMySamples() throws IOException {
		// TODO assert if right category (one of following)
		// List<String> asList = Arrays.asList("false-hits", "old-hits", "true-hits");

		CVEDetector sut = new CVEDetector(combined());

		List<String> filenames = filenames("my-log4j-samples");
		for (String filename : filenames) {
			if (isArchive(filename)) {
				System.out.println("-- " + filename);
				sut.check(filename);
				System.out.println();
			} else {
				// System.err.println("Ignoring " + file);
			}
		}

	}

	private Multiplexer combined() {

		// TODO shouldn't it be?
//		JndiManagerWithDirContextLookups vuln1 = new JndiManagerWithDirContextLookups();
		JndiManagerLookupCallsFromJndiLookup vuln1 = new JndiManagerLookupCallsFromJndiLookup();
		
		NamingContextLookupCallsFromJndiLookup vuln2 = new NamingContextLookupCallsFromJndiLookup();
		InitialContextLookupsCalls vuln3 = new InitialContextLookupsCalls();
		List<AbstractDetector> vulns = Arrays.asList(vuln1, vuln2, vuln3);
		
		// TODO verify if the class found by vulns are plugins
		Log4jPluginAnnotation isPlugin = new Log4jPluginAnnotation();
		IsJndiEnabledPropertyAccess isJndiEnabledPropertyAccess = new IsJndiEnabledPropertyAccess();

		List<AbstractDetector> all = new ArrayList<>(vulns);
		all.add(isJndiEnabledPropertyAccess);

		return new Multiplexer(all) {

			@Override
			public void visitEnd() {
				super.visitEnd();
				List<Detector> detectors = getDetections().stream().map(Detection::getDetector).collect(toList());

				// if we have Detections on classes (Paths) one of vulns, this is vulnerable IF
				// NOT we also have isJndiEnabledPropertyAccess

				boolean isVuln = vulns.stream().anyMatch(v -> detectors.contains(v));
				boolean hasPropertyAccess = detectors.contains(isJndiEnabledPropertyAccess);

				if (isVuln && !hasPropertyAccess) {
					System.err.println(getResource() + ": Log4J version with context lookup found (without "
							+ LOG4J2_ENABLE_JNDI + " check)");
				}
			}
		};

	}

	private List<String> filenames(String base) throws IOException {
		try (Stream<Path> fileStream = walk(Paths.get(base))) {
			return fileStream.filter(Files::isRegularFile).map(Path::toString).collect(toList());
		}
	}

}
