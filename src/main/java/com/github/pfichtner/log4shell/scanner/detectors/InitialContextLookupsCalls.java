package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.LOOKUP_NAME;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.isInitialContextLookup;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.util.LookupConstants;

/**
 * Searches in all classes in methods named {@value LookupConstants#LOOKUP_NAME}
 * for calls that are {@link LookupConstants#isInitialContextLookup()}.
 */
public class InitialContextLookupsCalls extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		methodInsnNodes(classNode, n -> typeComparator().methodNameIs(n, LOOKUP_NAME)).filter(isInitialContextLookup())
				.forEach(n -> addDetection(filename, classNode, referenceTo(n)));
	}

}
