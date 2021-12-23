package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.io.Files.isArchive;
import static com.github.pfichtner.log4shell.scanner.util.Streams.filter;
import static java.nio.file.Files.walk;
import static java.util.Arrays.asList;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toList;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.EnumSet;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detection;
import com.github.pfichtner.log4shell.scanner.Detectors.Multiplexer;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.InitialContextLookupsCalls;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiManager;
import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;
import com.github.pfichtner.log4shell.scanner.util.AsmUtil;

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

	private AbstractDetector combined() {
		/**
		 * <pre>
		 * 2.0-beta9, 2.0-rc1 -> Plugin direct calls (InitialContextLookupsCalls)
		 * 2.0-rc2, 2.0.1, 2.0.2, 2.0 -> NamingContextLookupCallsFromJndiLookup (the plugin)
		 * 2.1+ -> NamingContextLookupCallsFromJndiManager, JndiManagerLookupCallsFromJndiLookup (the plugin)
		 * </pre>
		 */

		Log4jPluginAnnotation plugins = new Log4jPluginAnnotation();
		InitialContextLookupsCalls initialContextLookupsCalls = new InitialContextLookupsCalls();
		NamingContextLookupCallsFromJndiLookup namingContextLookupCallsFromJndiLookup = new NamingContextLookupCallsFromJndiLookup();
		NamingContextLookupCallsFromJndiManager namingContextLookupCallsFromJndiManager = new NamingContextLookupCallsFromJndiManager();

		return new Multiplexer(asList(plugins, initialContextLookupsCalls, namingContextLookupCallsFromJndiLookup,
				namingContextLookupCallsFromJndiManager)) {

			@Override
			public void visitEnd() {
				for (Detection detection : plugins.getDetections()) {
					if (detectionsContains(initialContextLookupsCalls, detection.getIn())) {
						addDetection(detection.getFilename(), detection.getIn(),
								"Possible 2.0-beta9, 2.0-rc1 match "
										+ Type.getObjectType(detection.getIn().name).getClassName() + " in "
										+ detection.getFilename() + " of " + detection.getResource());
					} else if (detectionsContains(namingContextLookupCallsFromJndiLookup, detection.getIn())) {
						addDetection(detection.getFilename(), detection.getIn(),
								"Possible 2.0-rc2, 2.0.1, 2.0.2, 2.0 match "
										+ Type.getObjectType(detection.getIn().name).getClassName() + " in "
										+ detection.getFilename() + " of " + detection.getResource());
					} else {
						List<String> lookupCalls = namingContextLookupCallsFromJndiManager.getDetections().stream()
								.map(Detection::getIn).map(n -> n.name).collect(toList());
						List<String> allRefs = methodCallOwners(detection.getIn());
						if (lookupCalls.stream().anyMatch(l -> allRefs.contains(l))) {
							addDetection(detection.getFilename(), detection.getIn(),
									"Possible 2.1+ match " + Type.getObjectType(detection.getIn().name).getClassName()
											+ " in " + detection.getFilename() + " of " + detection.getResource());
						}
					}

				}
				super.visitEnd();
			}

			private List<String> methodCallOwners(ClassNode in) {
				return methodCalls(in).map(n -> n.owner).collect(toList());
			}

			private Stream<MethodInsnNode> methodCalls(ClassNode in) {
				return filter(in.methods.stream().map(AsmUtil::instructionsStream).flatMap(identity()),
						MethodInsnNode.class);
			}

			private boolean detectionsContains(AbstractDetector detector, ClassNode classNode) {
				return detector.getDetections().stream().map(Detection::getIn).anyMatch(classNode::equals);
			}
		};

	}

	private List<String> filenames(String base) throws IOException {
		try (Stream<Path> fileStream = walk(Paths.get(base))) {
			return fileStream.filter(Files::isRegularFile).map(Path::toString).collect(toList());
		}
	}

}
