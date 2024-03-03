package com.github.pfichtner.log4shell.scanner;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toSet;

import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.detectors.AbstractDetector;
import com.github.pfichtner.log4shell.scanner.detectors.DirContextLookupsCallsFromJndiManager;
import com.github.pfichtner.log4shell.scanner.detectors.InitialContextLookupsCalls;
import com.github.pfichtner.log4shell.scanner.detectors.IsJndiEnabledPropertyAccessWithJdbcPrefix;
import com.github.pfichtner.log4shell.scanner.detectors.JndiLookupConstructorWithISException;
import com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiLookup;
import com.github.pfichtner.log4shell.scanner.detectors.NamingContextLookupCallsFromJndiManager;

public class Log4JDetector extends AbstractDetector {

	/**
	 * <pre>
	 * 2.0-beta9, 2.0-rc1 -> Plugin direct calls (InitialContextLookupsCalls)
	 * 2.0-rc2, 2.0.1, 2.0.2, 2.0 -> NamingContextLookupCallsFromJndiLookup (the plugin)
	 * 2.1+ -> NamingContextLookupCallsFromJndiManager, JndiManagerLookupCallsFromJndiLookup (the plugin)
	 * </pre>
	 */

	private final Log4jPluginAnnotation plugins = new Log4jPluginAnnotation();
	private final InitialContextLookupsCalls initialContextLookupsCalls = new InitialContextLookupsCalls();
	private final NamingContextLookupCallsFromJndiLookup namingContextLookupCallsFromJndiLookup = new NamingContextLookupCallsFromJndiLookup();
	private final NamingContextLookupCallsFromJndiManager namingContextLookupCallsFromJndiManager = new NamingContextLookupCallsFromJndiManager();
	private final DirContextLookupsCallsFromJndiManager dirContextLookupsCallsFromJndiManager = new DirContextLookupsCallsFromJndiManager();

	private final JndiLookupConstructorWithISException jndiLookupConstructorWithISException = new JndiLookupConstructorWithISException();
	private final IsJndiEnabledPropertyAccessWithJdbcPrefix isJndiEnabledPropertyAccessWithJdbcPrefix = new IsJndiEnabledPropertyAccessWithJdbcPrefix();

	private final Multiplexer multiplexer = new Multiplexer(
			asList(plugins, initialContextLookupsCalls, namingContextLookupCallsFromJndiLookup,
					namingContextLookupCallsFromJndiManager, dirContextLookupsCallsFromJndiManager,
					jndiLookupConstructorWithISException, isJndiEnabledPropertyAccessWithJdbcPrefix));

	@Override
	public void visit(String resource) {
		multiplexer.visit(resource);
		super.visit(resource);
	}

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		multiplexer.visitClass(filename, classNode);
		super.visitClass(filename, classNode);
	}

	@Override
	public void visitFile(Path file, byte[] bytes) {
		multiplexer.visitFile(file, bytes);
		super.visitFile(file, bytes);
	}

	@Override
	public void visitEnd() {
		multiplexer.visitEnd();
		if (!isLog4j2171orGreater()) {
			for (Detection detection : plugins.getDetections()) {
				ClassNode detectionInClass = detection.getIn();
				if (detectionsOfContains(initialContextLookupsCalls, detectionInClass)) {
					reAdd(detection, "2.0-beta9, 2.0-rc1");
				} else if (detectionsOfContains(namingContextLookupCallsFromJndiLookup, detectionInClass)) {
					reAdd(detection, "2.0-rc2, 2.0.1, 2.0.2, 2.0");
				} else {
					Collection<String> allRefs = methodCallOwners(detectionInClass);
					if (detectionClassnames(dirContextLookupsCallsFromJndiManager).anyMatch(allRefs::contains)) {
						reAdd(detection, "2.15 <= x <= 2.16");
					} else if (detectionClassnames(namingContextLookupCallsFromJndiManager)
							.anyMatch(allRefs::contains)) {
						reAdd(detection, "2.1+");
					} else if (hasJndiLookupConstructorWithISException()) {
						reAdd(detection, "2.17.0");
					}
				}
			}
		}
		super.visitEnd();
	}

	private static Stream<String> detectionClassnames(AbstractDetector detector) {
		return detector.getDetections().stream().map(Detection::getIn).map(n -> n.name);
	}

	private void reAdd(Detection detection, String version) {
		addDetection(detection.getFilename(), detection.getIn(), "Possible " + version + " match");
	}

	private boolean isLog4j2171orGreater() {
		return !isJndiEnabledPropertyAccessWithJdbcPrefix.getDetections().isEmpty();
	}

	private boolean hasJndiLookupConstructorWithISException() {
		return !jndiLookupConstructorWithISException.getDetections().isEmpty();
	}

	private static Set<String> methodCallOwners(ClassNode classNode) {
		return methodInsnNodes(classNode, m -> true).map(n -> n.owner).collect(toSet());
	}

	private static boolean detectionsOfContains(AbstractDetector detector, ClassNode classNode) {
		return detectionsContains(detector.getDetections(), classNode);
	}

	private static boolean detectionsContains(List<Detection> detections, ClassNode classNode) {
		return detections.stream().map(Detection::getIn).anyMatch(classNode::equals);
	}

}