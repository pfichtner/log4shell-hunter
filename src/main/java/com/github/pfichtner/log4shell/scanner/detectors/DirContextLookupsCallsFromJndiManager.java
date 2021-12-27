package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.JNDI_MANAGER_TYPE;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.LOOKUP_NAME;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.dirContextLookup;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.throwsNamingException;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;

/**
 * <code>org/apache/logging/log4j/core/net/JndiManager#lookup(...) throws NamingException</code>
 * ---> <code>javax/naming/directory/DirContext#lookup(java.lang.String)<code>
 */
public class DirContextLookupsCallsFromJndiManager extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (typeComparator().isClass(classNode, JNDI_MANAGER_TYPE)) {
			methodInsnNodes(classNode, throwsNamingException().and(n -> typeComparator().methodNameIs(n, LOOKUP_NAME)))
					.filter(dirContextLookup()).forEach(n -> addDetection(filename, classNode, referenceTo(n)));
		}
	}

}
