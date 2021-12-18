package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.classIsJndiLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.methodNameIsLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.namingContextLookup;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

public class JndiLookupWithNamingContextLookupsWithoutThrowingException extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (classIsJndiLookup(filename)) {
			// TODO should be distinctBy target
			methodInsnNodes(classNode, methodNameIsLookup).filter(namingContextLookup).distinct()
					.forEach(n -> addDetections(filename, referenceTo(n)));
		}
	}

}
