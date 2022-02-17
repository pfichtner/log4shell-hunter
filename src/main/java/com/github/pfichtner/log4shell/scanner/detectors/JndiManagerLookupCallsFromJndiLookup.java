package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.JNDI_LOOKUP_TYPE;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.LOOKUP_NAME;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.isJndiManagerLookup;
import static com.github.pfichtner.log4shell.scanner.util.Streams.filter;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;
import com.github.pfichtner.log4shell.scanner.util.LookupConstants;

/**
 * Searches in classes {@value LookupConstants#JNDI_LOOKUP_TYPE} in methods
 * named {@value LookupConstants#LOOKUP_NAME} for calls that are
 * {@link LookupConstants#isJndiManagerLookup(AsmTypeComparator)}.
 */
public class JndiManagerLookupCallsFromJndiLookup extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		AsmTypeComparator typeComparator = typeComparator();
		if (typeComparator.isClass(classNode, JNDI_LOOKUP_TYPE)) {
			filter(methodInsnNodes(classNode, n -> typeComparator.methodNameIs(n, LOOKUP_NAME)), MethodInsnNode.class)
					.filter(isJndiManagerLookup(typeComparator))
					.forEach(n -> addDetection(filename, classNode, referenceTo(n)));
		}
	}

}
