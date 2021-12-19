package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess.LOG4J2_ENABLE_JNDI;
import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static java.nio.file.Files.walk;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detection;
import com.github.pfichtner.log4shell.scanner.Detectors.Multiplexer;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.InitialContextLookupsCalls;
import com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccess;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotationObfuscateAwareClassNodeCollector;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.io.Detector;
import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;

public class Log4jSamplesIT {

	@TestFactory
	Stream<DynamicTest> checkMergeBaseSamples() throws IOException {
		return forAllModes(() -> {
			// TODO assert if right category (one of following)
			// List<String> asList = Arrays.asList("false-hits", "old-hits", "true-hits");

			List<String> filenames = filenames("log4j-samples");
			assumeFalse(filenames.isEmpty(), "git submodule empty, please clone recursivly");
			doCheck(new CVEDetector(combined()), filenames);
		});

	}

	@TestFactory
	Stream<DynamicTest> checkMySamples() throws IOException {
		return forAllModes(() -> {
			// TODO assert if right category (one of following)
			// List<String> asList = Arrays.asList("false-hits", "old-hits", "true-hits");
			doCheck(new CVEDetector(combined()), filenames("my-log4j-samples"));
		});

	}

	private Stream<DynamicTest> forAllModes(Executable executable) {
		return EnumSet.allOf(AsmTypeComparator.class).stream().map(c -> dynamicTest(c.name(), () -> {
			System.out.println("*** using " + c);
			AsmTypeComparator.useTypeComparator(c);
			executable.execute();
		}));
	}

	private void doCheck(CVEDetector sut, List<String> filenames) throws IOException {
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

	private AbstractDetector combinedNext() {
		Log4jPluginAnnotationObfuscateAwareClassNodeCollector collector = new Log4jPluginAnnotationObfuscateAwareClassNodeCollector();
		AbstractDetector cacheAll = new AbstractDetector() {

			private final Map<Path, ClassNode> cached = new HashMap<>();

			@Override
			public void visitClass(Path filename, ClassNode classNode) {
				super.visitClass(filename, classNode);
				cached.put(filename, classNode);
			}

			@Override
			public void visitEnd() {
				super.visitEnd();
				List<Type> possiblePluginAnnoClasses = collector.getPossiblePluginAnnoClasses().values().stream()
						.map(n -> Type.getObjectType(n.name)).collect(toList());
				cached.entrySet().stream()
						.filter(e -> Log4jPluginAnnotation.hasPluginAnnotation(e.getValue(), possiblePluginAnnoClasses))
						.forEach(e -> addDetections(e.getKey(), "XXX"));
			}

		};

		return new Multiplexer(Arrays.asList(cacheAll, collector));

	}

	private AbstractDetector combined() {

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
