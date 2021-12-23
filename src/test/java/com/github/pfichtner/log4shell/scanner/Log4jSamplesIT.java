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
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Stream;

import org.assertj.core.internal.bytebuddy.jar.asm.MethodVisitor;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detection;
import com.github.pfichtner.log4shell.scanner.Detectors.Multiplexer;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.InitialContextLookupsCalls;
import com.github.pfichtner.log4shell.scanner.detectors.JndiLookupConstructorWithISException;
import com.github.pfichtner.log4shell.scanner.detectors.JndiManagerLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotationObfuscateAwareClassNodeCollector;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiManager;
import com.github.pfichtner.log4shell.scanner.io.Detector;
import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;
import com.github.pfichtner.log4shell.scanner.util.AsmUtil;
import com.github.pfichtner.log4shell.scanner.util.LookupConstants;

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

	// TODO fails(?) finding matches in nested archives
	private AbstractDetector combined_NEXT() {
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
						.forEach(e -> addDetections(e.getKey(), e.getValue(),
								"Possible " + LookupConstants.PLUGIN_TYPE));
				cached.clear();
			}

		};

		return new Multiplexer(asList(cacheAll, collector));

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
						System.err.println("Possible 2.0-beta9, 2.0-rc1 match "
								+ Type.getObjectType(detection.getIn().name).getClassName() + " in "
								+ detection.getFilename() + " of " + detection.getResource());
					} else if (detectionsContains(namingContextLookupCallsFromJndiLookup, detection.getIn())) {
						System.err.println("Possible 2.0-rc2, 2.0.1, 2.0.2, 2.0 match "
								+ Type.getObjectType(detection.getIn().name).getClassName() + " in "
								+ detection.getFilename() + " of " + detection.getResource());
					} else {
						List<String> lookupCalls = namingContextLookupCallsFromJndiManager.getDetections().stream()
								.map(Detection::getIn).map(n -> n.name).collect(toList());
						List<String> allRefs = methodCallOwners(detection.getIn());
						if (lookupCalls.stream().anyMatch(l -> allRefs.contains(l))) {
							System.err.println(
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

	private AbstractDetector combinedOLD() {

		// TODO shouldn't it be?
//		JndiManagerWithDirContextLookups vuln1 = new JndiManagerWithDirContextLookups();
		JndiManagerLookupCallsFromJndiLookup vuln1 = new JndiManagerLookupCallsFromJndiLookup();

		NamingContextLookupCallsFromJndiLookup vuln2 = new NamingContextLookupCallsFromJndiLookup();
		InitialContextLookupsCalls vuln3 = new InitialContextLookupsCalls();
		List<AbstractDetector> vulns = asList(vuln1, vuln2, vuln3);

		// TODO verify if the class found by vulns are plugins
		Log4jPluginAnnotation isPlugin = new Log4jPluginAnnotation();
		JndiLookupConstructorWithISException isAtLeastLog4J217 = new JndiLookupConstructorWithISException();

		List<AbstractDetector> all = new ArrayList<>(vulns);
		all.add(isAtLeastLog4J217);

		return new Multiplexer(all) {

			private String resource;

			@Override
			public void visit(String resource) {
				this.resource = resource;
				super.visit(resource);
			}

			@Override
			public void visitEnd() {
				super.visitEnd();
				List<Detector> detectors = getDetections().stream().filter(isFalsePositivesLog4J().negate())
						.map(Detection::getDetector).collect(toList());

				// if we have Detections on classes (Paths) one of vulns, this is vulnerable IF
				// NOT we also have isJndiEnabledPropertyAccess

				boolean isVuln = vulns.stream().anyMatch(v -> detectors.contains(v));
				boolean hasPropertyAccess = detectors.contains(isAtLeastLog4J217);

				if (isVuln && !hasPropertyAccess) {
					System.err.println(resource
							+ ": Log4J version with context lookup found (without code introduced in log4j-2.17)");
				}
			}

			/**
			 * Filter out false positives on naming context lookups. In fact this is only
			 * needed when running in mode where classnames and methodnames are ignored
			 * (obfuscated).
			 */
			private Predicate<Detection> isFalsePositivesLog4J() {
				return new Predicate<Detection>() {

					List<String> classesWithNamingContexLookupCalls = asList( //
							"/net/JMSSink.class", //
							"/net/JMSAppender.class", //
							"/core/selector/JNDIContextSelector.class", //
							"/core/net/JMSTopicReceiver.class", //
							"/core/net/JMSQueueReceiver.class", //
							"/core/net/AbstractJMSReceiver.class", //
							"/core/net/AbstractJMSManager.class");

					@Override
					public boolean test(Detection detection) {
						return detection.getDetector().getClass() == NamingContextLookupCallsFromJndiLookup.class
								&& classesWithNamingContexLookupCalls.stream()
										.anyMatch(detection.getFilename().toString()::endsWith);
					}
				};
			}
		};

	}

	private List<String> filenames(String base) throws IOException {
		try (Stream<Path> fileStream = walk(Paths.get(base))) {
			return fileStream.filter(Files::isRegularFile).map(Path::toString).collect(toList());
		}
	}

}
