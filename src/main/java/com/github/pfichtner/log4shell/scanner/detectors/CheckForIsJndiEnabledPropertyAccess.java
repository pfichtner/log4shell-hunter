package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.Streams.filter;
import static java.util.function.Function.identity;
import static org.objectweb.asm.Opcodes.ICONST_0;

import java.nio.file.Path;
import java.util.function.Predicate;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;
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
public class CheckForIsJndiEnabledPropertyAccess implements Detector<Detections> {

	private static final String LOG4J2_ENABLE_JNDI = "log4j2.enableJndi";

	private static final Predicate<LdcInsnNode> constantPoolLoad = n -> LOG4J2_ENABLE_JNDI.equals(n.cst);

	private static final Predicate<LdcInsnNode> possiblyAccessToGetBooleanProperty = constantPoolLoad.and(n -> {
		AbstractInsnNode next = n.getNext();
		return next instanceof InsnNode && next.getOpcode() == ICONST_0;
	});

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		// LdcInsn("log4j2.enableJndi");
		// Insn(ICONST_0);
		filter(classNode.methods.stream().map(AsmUtil::instructionsStream).flatMap(identity()), LdcInsnNode.class)
				.filter(possiblyAccessToGetBooleanProperty).forEach(_i -> detections.add(this, filename));
	}

	@Override
	public String format(Detection detection) {
		return LOG4J2_ENABLE_JNDI + " access";
	}

}
