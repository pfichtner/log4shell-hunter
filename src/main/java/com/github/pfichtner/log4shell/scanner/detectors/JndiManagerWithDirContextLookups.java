package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.repackageComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.JNDI_MANAGER_TYPE;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.dirContextLookup;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.methodNameIsLookup;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.throwsNamingException;

import java.nio.file.Path;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;

public class JndiManagerWithDirContextLookups extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (repackageComparator.isClass(Type.getObjectType(classNode.name), JNDI_MANAGER_TYPE)) {
			methodInsnNodes(classNode, methodNameIsLookup.and(throwsNamingException)).filter(dirContextLookup)
					.distinct().forEach(n -> addDetections(filename, referenceTo(n)));
		}
	}

}
