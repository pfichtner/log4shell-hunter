package com.github.pfichtner.log4shell.scanner.visitor;

import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.methodName;
import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.nullSafety;
import static org.objectweb.asm.Opcodes.INVOKEINTERFACE;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public final class JndiUtil {

	private JndiUtil() {
		super();
	}

	public interface MethodInsnNodeComparator {
		String handle(MethodInsnNode node);
	}

	// TODO do not depend on method name
	public static final Predicate<MethodNode> nameIsLookup = methodNode -> methodNode.name.equals("lookup");

	public static final Predicate<MethodNode> throwsNamingException = methodNode -> doesThrow(methodNode.exceptions,
			"javax/naming/NamingException");

	public static Set<Optional<String>> hasJndiManagerLookupImpl(ClassNode classNode,
			Predicate<MethodNode> methodNodePredicate, MethodInsnNodeComparator... nodeComparators) {
		Set<Optional<String>> hits = new LinkedHashSet<>();
		for (MethodNode methodNode : classNode.methods) {
			if (methodNodePredicate.test(methodNode)) {
				for (AbstractInsnNode insnNode : methodNode.instructions) {
					if (insnNode instanceof MethodInsnNode) {
						MethodInsnNode methodInsnNode = (MethodInsnNode) insnNode;
						for (MethodInsnNodeComparator nodeComparator : nodeComparators) {
							hits.add(Optional.ofNullable(nodeComparator.handle(methodInsnNode)));
						}
					}
				}
			}

		}
		return hits;
	}

	private static boolean doesThrow(List<String> exceptions, String... types) {
		return Arrays.asList(types).equals(nullSafety(exceptions));
	}

	public static final MethodInsnNodeComparator namingContext = node -> ("(Ljava/lang/String;)Ljava/lang/Object;"
			.equals(node.desc)) && "javax/naming/Context".equals(node.owner) && "lookup".equals(node.name)
			&& INVOKEINTERFACE == node.getOpcode() ? "Reference to " + "javax.naming.Context#lookup(java.lang.String)"
					: null;

	public static final MethodInsnNodeComparator initialContext = node -> ("(Ljava/lang/String;)Ljava/lang/Object;"
			.equals(node.desc)) && "javax/naming/InitialContext".equals(node.owner) && "lookup".equals(node.name)
			&& INVOKEVIRTUAL == node.getOpcode() ? "Reference to " + "javax.naming.Context#lookup(java.lang.String)"
					: null;

	public static final MethodInsnNodeComparator dirContext = node -> ("(Ljava/lang/String;)Ljava/lang/Object;"
			.equals(node.desc) || "(Ljava/lang/String;)Ljavax/naming/directory/Attributes;".equals(node.desc))
			&& "javax/naming/directory/DirContext".equals(node.owner) && "lookup".equals(node.name)
			&& INVOKEINTERFACE == node.getOpcode() ? "Reference to " + methodName(node) : null;
}
