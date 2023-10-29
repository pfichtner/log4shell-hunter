package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.constantPoolLoadOf;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.instructionsStream;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.opCodeIs;
import static com.github.pfichtner.log4shell.scanner.util.Streams.filter;
import static java.util.stream.Collectors.toList;
import static org.objectweb.asm.Opcodes.INVOKESTATIC;

import java.nio.file.Path;
import java.util.List;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import com.github.pfichtner.log4shell.scanner.util.AsmUtil;

/**
 * Searches for classes that have references to methods having loads of constant
 * pool entries x and y.
 */
public class IsJndiEnabledPropertyAccessWithJdbcPrefix extends AbstractDetector {

	private static final String PREFIX = "log4j2.enableJndi";
	private static final String JDBC_SUFFIX = "Jdbc";

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		List<MethodNode> methodsWithPossibleCallsToGetBooleanProperty = classNode.methods.stream().filter(
				m -> filter(instructionsStream(m), LdcInsnNode.class).anyMatch(constantPoolLoadOf(PREFIX::equals)))
				.collect(toList());

		// no need to deep dive into it if we don't have any methods to match
		if (!methodsWithPossibleCallsToGetBooleanProperty.isEmpty()) {
			if (classNode.methods.stream().filter(AsmUtil::isStatic)
					.anyMatch(m -> filter(instructionsStream(m), LdcInsnNode.class).anyMatch(constantPoolLoadOf(
							JDBC_SUFFIX::equals)
							.and(n -> methodHasCallTo(m, classNode, methodsWithPossibleCallsToGetBooleanProperty))))) {
				addDetection(filename, classNode, PREFIX + JDBC_SUFFIX + " access");
			}
		}
	}

	private boolean methodHasCallTo(MethodNode method, ClassNode classNode,
			List<MethodNode> methodsWithPossibleCallsToGetBooleanProperty) {
		return filter(instructionsStream(method), MethodInsnNode.class)
				.anyMatch(n -> isCallTo(classNode, n, methodsWithPossibleCallsToGetBooleanProperty));
	}

	private boolean isCallTo(ClassNode classNode, MethodInsnNode node,
			List<MethodNode> methodsWithPossibleCallsToGetBooleanProperty) {
		return opCodeIs(node, INVOKESTATIC) && calledMethodIsInClass(classNode, node)
				&& methodsWithPossibleCallsToGetBooleanProperty.stream()
						.anyMatch(m -> m.name.equals(node.name) && m.desc.equals(node.desc));
	}

	private boolean calledMethodIsInClass(ClassNode classNode, MethodInsnNode insnNode) {
		return insnNode.owner.equals(classNode.name);
	}

}
