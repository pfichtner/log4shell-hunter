package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.constantPoolLoadOf;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.nexts;
import static com.github.pfichtner.log4shell.scanner.util.Streams.filter;
import static java.util.function.Function.identity;
import static org.objectweb.asm.Opcodes.ICONST_0;

import java.nio.file.Path;
import java.util.stream.Stream;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;

import com.github.pfichtner.log4shell.scanner.util.AsmUtil;

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

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		// LdcInsn("log4j2.enableJndi");
		// Insn(ICONST_0);
		filter(instructions(classNode), LdcInsnNode.class) //
				.filter(constantPoolLoadOf(LOG4J2_ENABLE_JNDI::equals)) //
				.filter(n -> nextsContainAny(n, ICONST_0)) //
				.forEach(__ -> addDetection(filename, classNode, LOG4J2_ENABLE_JNDI + " access"));
	}

	private static Stream<AbstractInsnNode> instructions(ClassNode classNode) {
		return classNode.methods.stream().map(AsmUtil::instructionsStream).flatMap(identity());
	}

	private static boolean nextsContainAny(AbstractInsnNode node, int opcode) {
		return nexts(node).anyMatch(n -> n.getOpcode() == opcode);
	}

}
