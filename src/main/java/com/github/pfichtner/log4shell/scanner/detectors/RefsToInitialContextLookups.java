package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.initialContextLookup;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.methodNameIsLookup;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

/**
 * log4j-core-2.0-beta9 and log4j-core-2.0-rc1 did not have a JndiManager but
 * did JNDI access by themselves.
 */
public class RefsToInitialContextLookups extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		methodInsnNodes(classNode, methodNameIsLookup).filter(initialContextLookup).distinct()
				.forEach(n -> addDetections(filename, referenceTo(n)));
	}

}
