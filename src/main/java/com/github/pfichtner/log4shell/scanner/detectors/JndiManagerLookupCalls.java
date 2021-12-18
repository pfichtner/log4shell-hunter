package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.classIsJndiLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.jndiManagerLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.methodNameIsLookup;
import static com.github.pfichtner.log4shell.scanner.util.Streams.filter;
import static java.util.function.Function.identity;

import java.nio.file.Path;
import java.util.stream.Stream;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Detector;
import com.github.pfichtner.log4shell.scanner.util.AsmUtil;

/**
 * Detects calls in classes that are named <code>JndiLookup</code> to
 * org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String)
 */
public class JndiManagerLookupCalls implements Detector<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		if (classIsJndiLookup(filename)) {
			jndiManagerLookupCalls(classNode).forEach(n -> detections.add(this, filename, Detector.referenceTo(n)));
		}
	}

	private Stream<MethodInsnNode> jndiManagerLookupCalls(ClassNode classNode) {
		// TODO JndiManager could be renamed and obfuscated too, so how can we check if
		// this is a reference to
		// https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java
		return filter(classNode.methods.stream().filter(methodNameIsLookup).map(AsmUtil::instructionsStream)
				.flatMap(identity()), MethodInsnNode.class).filter(jndiManagerLookup);
	}

}
