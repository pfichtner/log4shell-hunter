package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator.typeComparator;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.constantPoolLoadOf;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.instructionsStream;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.isConstructor;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.voidNoArgs;
import static com.github.pfichtner.log4shell.scanner.util.LookupConstants.JNDI_LOOKUP_TYPE;
import static com.github.pfichtner.log4shell.scanner.util.Streams.filter;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;

import com.github.pfichtner.log4shell.scanner.util.LookupConstants;

/**
 * Searches in classes {@value LookupConstants#JNDI_LOOKUP_TYPE} noarg
 * constructor for statements referring
 * {@value #JNDI_MUST_BE_ENABLED_BY_SETTING}.
 * 
 * With log4j-core-2.17 the constructor of JndiLookup throws
 * <code>IllegalStateException</code>s.
 */
public class JndiLookupConstructorWithISException extends AbstractDetector {

	private static final String JNDI_MUST_BE_ENABLED_BY_SETTING = "JNDI must be enabled by setting log4j2.enableJndiLookup=true";

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (typeComparator().isClass(classNode, JNDI_LOOKUP_TYPE)) {
			classNode.methods.stream().filter(isConstructor().and(voidNoArgs())).findFirst().ifPresent(c -> {
				filter(instructionsStream(c), LdcInsnNode.class)
						.filter(constantPoolLoadOf(JNDI_MUST_BE_ENABLED_BY_SETTING::equals))
						.forEach(_i -> addDetection(filename, classNode, JNDI_MUST_BE_ENABLED_BY_SETTING + " access"));
			});
		}
	}

}
