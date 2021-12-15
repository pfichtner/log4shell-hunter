package com.github.pfichtner.log4shell.scanner.visitor;

import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.isClass;
import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.methodName;
import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.nullSafety;
import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.readClass;
import static org.objectweb.asm.Opcodes.INVOKEINTERFACE;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CheckForJndiManagerWithContextLookups implements Visitor<Detections> {

	interface MethodInsnNodeComparator {
		String handle(MethodInsnNode node);
	}

	public static final MethodInsnNodeComparator namingContext = node -> ("(Ljava/lang/String;)Ljava/lang/Object;"
			.equals(node.desc)) && "javax/naming/Context".equals(node.owner) && "lookup".equals(node.name)
			&& INVOKEINTERFACE == node.getOpcode() ? "Reference to " + "javax.naming.Context#lookup(java.lang.String)"
					: null;

	public static final MethodInsnNodeComparator dirContext = node -> ("(Ljava/lang/String;)Ljava/lang/Object;"
			.equals(node.desc) || "(Ljava/lang/String;)Ljavax/naming/directory/Attributes;".equals(node.desc))
			&& "javax/naming/directory/DirContext".equals(node.owner) && "lookup".equals(node.name)
			&& INVOKEINTERFACE == node.getOpcode() ? "Reference to " + methodName(node) : null;

	private final MethodInsnNodeComparator[] nodeComparators;

	public CheckForJndiManagerWithContextLookups() {
		this(namingContext, dirContext);
	}

	public CheckForJndiManagerWithContextLookups(MethodInsnNodeComparator... nodeComparators) {
		this.nodeComparators = nodeComparators.clone();
	}

	@Override
	public void visit(Detections detections, String filename, byte[] bytes) {
		// TODO do not depend on filename (classname)
		if (isClass(filename) && filename.contains("JndiManager")) {
			searchContextLookups(bytes).stream().filter(Optional::isPresent).map(Optional::get)
					.map(s -> s.concat(" found in class " + filename)).forEach(detections::add);
		}
	}

	private Set<Optional<String>> searchContextLookups(byte[] bytes) {
		return hasJndiManagerLookupImpl(readClass(bytes, 0));
	}

	private Set<Optional<String>> hasJndiManagerLookupImpl(ClassNode classNode) {
		Set<Optional<String>> hits = new LinkedHashSet<>();
		for (MethodNode methodNode : classNode.methods) {
			if (methodNode.name.equals("lookup") && doesThrow(methodNode.exceptions, "javax/naming/NamingException")) {
				for (AbstractInsnNode insnNode : methodNode.instructions) {
					// TODO do not depend on method name
					if (methodNode.name.equals("lookup") && insnNode instanceof MethodInsnNode) {
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

	private boolean doesThrow(List<String> exceptions, String... types) {
		return Arrays.asList(types).equals(nullSafety(exceptions));
	}

}
