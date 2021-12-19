package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.JNDI_MANAGER_TYPE;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.LOOKUP_NAME;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.namingContextLookup;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.throwsNamingException;

import java.nio.file.Path;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;

/**
 * org/apache/logging/log4j/core/net/JndiManager#lookup -->
 * javax/naming/Context#lookup
 */
public class NamingContextLookupCallsFromJndiManager extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (typeComparator().isClass(Type.getObjectType(classNode.name), JNDI_MANAGER_TYPE)) {
			methodInsnNodes(classNode, throwsNamingException.and(n -> typeComparator().methodNameIs(n, LOOKUP_NAME)))
					.filter(namingContextLookup).distinct().forEach(n -> addDetections(filename, classNode, referenceTo(n)));
		}
	}

}
