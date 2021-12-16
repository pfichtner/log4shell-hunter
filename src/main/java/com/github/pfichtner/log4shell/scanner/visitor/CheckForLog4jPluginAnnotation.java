package com.github.pfichtner.log4shell.scanner.visitor;

import static com.github.pfichtner.log4shell.scanner.visitor.AsmUtil.nullSafety;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.hasJndiManagerLookupImpl;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.initialContext;
import static com.github.pfichtner.log4shell.scanner.visitor.JndiUtil.nameIsLookup;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Visitor;

public class CheckForLog4jPluginAnnotation implements Visitor<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		if (hasPluginAnnotation(classNode)) {
			detections.add("@Plugin(name = \"jndi\", category = \"Lookup\") found in class " + filename);
			refsToContext(classNode, detections, filename).forEach(detections::add);
		}
	}

	private static boolean hasPluginAnnotation(ClassNode classNode) {
		for (AnnotationNode annotationNode : nullSafety(classNode.visibleAnnotations)) {
			// TODO build a map of annotations and verify if they match the properties of
			// org.apache.logging.log4j.plugins.Plugin (TODO define which log4j version
			// Plugins included what attributes)
			if ("Lorg/apache/logging/log4j/core/config/plugins/Plugin;".equals(annotationNode.desc)) {
				Map<Object, Object> values = AsmUtil.toMap(annotationNode, annotationNode.values);
				// @Plugin(name = "jndi", category = "Lookup")
				if ("jndi".equals(values.get("name")) && "Lookup".equals(values.get("category"))) {
					return true;
				}
			}
		}
		return false;
	}

	private Stream<String> refsToContext(ClassNode classNode, Detections detections, Path filename) {
		return hasJndiManagerLookupImpl(classNode, nameIsLookup, initialContext).stream().filter(Optional::isPresent)
				.map(Optional::get).map(s -> s.concat(" found in class " + filename));
	}

}
