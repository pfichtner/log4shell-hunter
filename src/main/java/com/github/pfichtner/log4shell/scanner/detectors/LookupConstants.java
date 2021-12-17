package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.nullSafety;
import static org.objectweb.asm.Opcodes.INVOKEINTERFACE;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public final class LookupConstants {

	private LookupConstants() {
		super();
	}

	// TODO do not depend on method name
	public static final Predicate<MethodNode> methodNameIsLookup = methodNameIs("lookup");

	// TODO do not depend on class name
	public static boolean classIsJndiLookup(Path filename) {
		return filename.toString().endsWith("JndiLookup.class");
	}

	// TODO do not depend on class name
	public static boolean classIsJndiManager(Path filename) {
		return filename.toString().endsWith("JndiManager.class");
	}

	public static Predicate<MethodNode> methodNameIs(String name) {
		return methodNode -> methodNode.name.equals(name);
	}

	public static final Predicate<MethodNode> throwsNamingException = methodNode -> doesThrow(methodNode.exceptions,
			"javax/naming/NamingException");

	private static boolean doesThrow(List<String> exceptions, String... types) {
		return Arrays.asList(types).equals(nullSafety(exceptions));
	}

	public static final Predicate<MethodInsnNode> namingContextLookup = node -> ("(Ljava/lang/String;)Ljava/lang/Object;"
			.equals(node.desc)) && "javax/naming/Context".equals(node.owner) && "lookup".equals(node.name)
			&& INVOKEINTERFACE == node.getOpcode();

	public static final Predicate<MethodInsnNode> initialContextLookup = node -> ("(Ljava/lang/String;)Ljava/lang/Object;"
			.equals(node.desc)) && "javax/naming/InitialContext".equals(node.owner) && "lookup".equals(node.name)
			&& INVOKEVIRTUAL == node.getOpcode();

	public static final Predicate<MethodInsnNode> dirContextLookup = node -> ("(Ljava/lang/String;)Ljava/lang/Object;"
			.equals(node.desc) || "(Ljava/lang/String;)Ljavax/naming/directory/Attributes;".equals(node.desc))
			&& "javax/naming/directory/DirContext".equals(node.owner) && "lookup".equals(node.name)
			&& INVOKEINTERFACE == node.getOpcode();

}
