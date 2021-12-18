package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.repackageComparator;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.JNDI_LOOKUP_TYPE;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.jndiManagerLookup;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.methodNameIsLookup;
import static com.github.pfichtner.log4shell.scanner.util.Streams.filter;
import static java.util.function.Function.identity;

import java.nio.file.Path;
import java.util.stream.Stream;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.util.AsmUtil;

/**
 * Detects calls in classes that are named <code>JndiLookup</code> to
 * org.apache.logging.log4j.core.net.JndiManager#lookup(java.lang.String)
 */
public class JndiManagerLookupCalls extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (repackageComparator.isClass(Type.getObjectType(classNode.name), JNDI_LOOKUP_TYPE)) {
			jndiManagerLookupCalls(classNode).forEach(n -> addDetections(filename, referenceTo(n)));
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
