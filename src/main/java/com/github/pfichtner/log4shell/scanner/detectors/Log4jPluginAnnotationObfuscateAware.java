package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation.CATEGORY_LOOKUP;
import static com.github.pfichtner.log4shell.scanner.detectors.Log4jPluginAnnotation.NAME_JNDI;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.isAnno;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.nullSafety;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.toMap;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

public class Log4jPluginAnnotationObfuscateAware extends AbstractDetector {

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		if (isAnno(classNode) && couldBePluginAnno(filename, classNode)) {
			System.out.println("Possible Plugin anno" + filename);
		}
		if (hasPluginAnnotation(classNode)) {
			addDetections(filename, "@Plugin(name = \"" + NAME_JNDI + "\", category = \"" + CATEGORY_LOOKUP + "\")");
		}
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

	private static boolean hasPluginAnnotation(ClassNode classNode) {
		for (AnnotationNode annotationNode : nullSafety(classNode.visibleAnnotations)) {
			// TODO build a map of annotations and verify if they match the properties of
			// org.apache.logging.log4j.plugins.Plugin (TODO define which log4j version
			// Plugins included what attributes)
			if ("Lorg/apache/logging/log4j/core/config/plugins/Plugin;".equals(annotationNode.desc)) {
				Map<Object, Object> values = toMap(annotationNode);
				// @Plugin(xxxxx = "jndi", yyyyyyyyyyyyyy = "Lookup")
				if (values.containsValue(NAME_JNDI) && values.containsValue(CATEGORY_LOOKUP)) {
					return true;
				}
			}
		}
		return false;
	}

}
