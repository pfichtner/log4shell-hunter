package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.JNDI_MANAGER_TYPE;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.LOOKUP_NAME;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.isNamingContextLookup;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.throwsNamingException;

import java.nio.file.Path;
import java.util.stream.Stream;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.util.LookupConstants;

/**
 * Searches in classes {@value LookupConstants#JNDI_MANAGER_TYPE} in methods
 * named {@value LookupConstants#LOOKUP_NAME} and throws
 * {@value LookupConstants#JAVAX_NAMING_NAMING_EXCEPTION} for calls that are
 * {@link LookupConstants#isNamingContextLookup()}.
 */
public class NamingContextLookupCallsFromJndiManager extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (typeComparator().isClass(classNode, JNDI_MANAGER_TYPE)) {
			matches(classNode).forEach(n -> addDetection(filename, classNode, referenceTo(n)));
		}
	}

	private Stream<MethodInsnNode> matches(ClassNode classNode) {
		return methodInsnNodes(classNode,
				throwsNamingException().and(n -> typeComparator().methodNameIs(n, LOOKUP_NAME)))
						.filter(isNamingContextLookup());
	}

}
