package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.JNDI_MANAGER_TYPE;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.LOOKUP_NAME;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.isDirContextLookup;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.throwsNamingException;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.util.LookupConstants;

/**
 * Searches in classes {@value LookupConstants#JNDI_MANAGER_TYPE} in methods
 * named {@value LookupConstants#LOOKUP_NAME} and throws
 * {@value LookupConstants#JAVAX_NAMING_NAMING_EXCEPTION} for calls that are
 * {@link LookupConstants#isDirContextLookup()}.
 */
public class DirContextLookupsCallsFromJndiManager extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (typeComparator().isClass(classNode, JNDI_MANAGER_TYPE)) {
			methodInsnNodes(classNode, throwsNamingException().and(n -> typeComparator().methodNameIs(n, LOOKUP_NAME)))
					.filter(isDirContextLookup()).forEach(n -> addDetection(filename, classNode, referenceTo(n)));
		}
	}

}
