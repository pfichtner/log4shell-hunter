package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.constantPoolLoadOf;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.hasOpCode;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.instructionsStream;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.nexts;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.returnTypeIs;
import static com.github.pfichtner.log4shell.scanner.util.Streams.filter;
import static org.objectweb.asm.Opcodes.ICONST_0;
import static org.objectweb.asm.Type.BOOLEAN_TYPE;
import static org.objectweb.asm.Type.getObjectType;

import java.nio.file.Path;
import java.util.function.Predicate;

import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.util.AsmTypeComparator;

/**
 * Searches for methods that loads {@value #LOG4J2_ENABLE_JNDI} from the
 * constant pool. This was introduced with log4j-core-2.16.0/log4j-core-2.12.2.
 * 
 * <pre>
 * public static boolean isJndiEnabled() {
 * 	return PropertiesUtil.getProperties().getBooleanProperty("log4j2.enableJndi", false);
 * }
 * </pre>
 * 
 * We do NOT check the method <code>isJndiEnabled</code> nor the access of
 * #getBooleanProperty since all of them could have been inlined by the
 * compiler. <br>
 * Beside that we look for if there is an <code>ICONST_0</code>
 * (<code>false</code>) directly after {@value #LOG4J2_ENABLE_JNDI} load on the
 * stack.
 */
public class IsJndiEnabledPropertyAccess extends AbstractDetector {

	public static final String LOG4J2_ENABLE_JNDI = "log4j2.enableJndi";

	// mv.visitInsn(ICONST_0);
	// mv.visitMethodInsn(INVOKEVIRTUAL,
	// "org/apache/logging/log4j/util/PropertiesUtil", "getBooleanProperty",
	// "(Ljava/lang/String;Z)Z", false);
	private static final Predicate<AbstractInsnNode> callGetBooleanPropertyWithFalse = hasOpCode(ICONST_0)
			.and(n -> isCallToMethodThatReturnsBoolean(n.getNext()));

	private static final Type PROPERTIESUTIL_TYPE = getObjectType("org/apache/logging/log4j/util/PropertiesUtil");

	private static boolean isCallToMethodThatReturnsBoolean(AbstractInsnNode node) {
		if (!(node instanceof MethodInsnNode)) {
			return false;
		}
		MethodInsnNode methodInsnNode = (MethodInsnNode) node;
		if (!returnTypeIs(methodInsnNode, BOOLEAN_TYPE)) {
			return false;
		}

		AsmTypeComparator typeComparator = AsmTypeComparator.typeComparator();
		return typeComparator == AsmTypeComparator.obfuscatorComparator
				|| (typeComparator.isClass(getObjectType(methodInsnNode.owner), PROPERTIESUTIL_TYPE)
						&& "getBooleanProperty".equals(methodInsnNode.name)
						&& "(Ljava/lang/String;Z)Z".equals(methodInsnNode.desc));
	}

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		// LdcInsn("log4j2.enableJndi");
		classNode.methods.stream().forEach(m -> {
			filter(instructionsStream(m), LdcInsnNode.class) //
					.filter(constantPoolLoadOf(LOG4J2_ENABLE_JNDI::equals)) //
					.filter(i -> nexts(i).anyMatch(callGetBooleanPropertyWithFalse)) //
					.forEach(__ -> addDetection(filename, classNode, LOG4J2_ENABLE_JNDI + " access"));
		});

	}

}
