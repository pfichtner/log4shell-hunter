package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.isAnno;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.nullSafety;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

public class Log4jPluginAnnotationObfuscateAwareClassNodeCollector extends AbstractDetector {

	private Map<Path, ClassNode> possiblePluginAnnoClasses;

	@Override
	public void visit(String resource) {
		super.visit(resource);
		possiblePluginAnnoClasses = new HashMap<>();
	}

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (isAnno(classNode) && couldBePluginAnno(filename, classNode)) {
			possiblePluginAnnoClasses.put(filename, classNode);
		}
	}

	public Map<Path, ClassNode> getPossiblePluginAnnoClasses() {
		return possiblePluginAnnoClasses;
	}

	private boolean couldBePluginAnno(Path filename, ClassNode classNode) {
		if (!hasRetentionPolicy(classNode, "RUNTIME")) {
			return false;
		}
		// String name(), String category(), String elementType() default EMPTY
		List<MethodNode> methodsThatReturnsStrings = classNode.methods.stream()
				.filter(n -> n.desc.equals("()Ljava/lang/String;")).collect(Collectors.toList());
		long methodsThatReturnsStringsWithDefaultEmptyString = methodsThatReturnsStrings.stream()
				.filter(n -> "".equals(n.annotationDefault)).count();
		return methodsThatReturnsStrings.size() == 3 //
				&& methodsThatReturnsStringsWithDefaultEmptyString == 1;
	}

	private boolean hasRetentionPolicy(ClassNode classNode, String policy) {
		return nullSafety(classNode.visibleAnnotations).stream()
				.filter(a -> a.desc.equals("Ljava/lang/annotation/Retention;"))
				.anyMatch(an -> an.desc.equals("Ljava/lang/annotation/Retention;") && an.values.size() == 2
						&& an.values.get(0).equals("value") && an.values.get(1) instanceof String[]
						&& Arrays.equals((String[]) an.values.get(1),
								new String[] { "Ljava/lang/annotation/RetentionPolicy;", policy }));
	}

}
