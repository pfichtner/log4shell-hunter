package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.classIsJndiManager;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.dirContextLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.methodNameIsLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.throwsNamingException;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

public class JndiManagerWithDirContextLookups extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (classIsJndiManager(filename)) {
			// TODO should be distinctBy target
			methodInsnNodes(classNode, methodNameIsLookup.and(throwsNamingException)).filter(dirContextLookup)
					.distinct().forEach(n -> addDetections(filename, referenceTo(n)));
		}
	}

}
