package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.initialContextLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.methodNameIsLookup;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

public class RefsToInitialContextLookups extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		// TODO should be distinctBy target
		methodInsnNodes(classNode, methodNameIsLookup).filter(initialContextLookup).distinct()
				.forEach(n -> addDetections(filename, referenceTo(n)));
	}

}
