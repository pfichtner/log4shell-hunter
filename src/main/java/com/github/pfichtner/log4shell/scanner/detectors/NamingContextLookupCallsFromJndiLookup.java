package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.JNDI_LOOKUP_TYPE;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.LOOKUP_NAME;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.isNamingContextLookup;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.util.LookupConstants;

/**
 * Searches in classes {@value LookupConstants#JNDI_LOOKUP_TYPE} in methods
 * named {@value LookupConstants#LOOKUP_NAME} for calls that are
 * {@link LookupConstants#isNamingContextLookup()}.
 */
public class NamingContextLookupCallsFromJndiLookup extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (typeComparator().isClass(classNode, JNDI_LOOKUP_TYPE)) {
			methodInsnNodes(classNode, n -> typeComparator().methodNameIs(n, LOOKUP_NAME))
					.filter(isNamingContextLookup()).forEach(n -> addDetection(filename, classNode, referenceTo(n)));
		}
	}

}
