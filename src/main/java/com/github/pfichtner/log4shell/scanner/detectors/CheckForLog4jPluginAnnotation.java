package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.nullSafety;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.toMap;

import java.nio.file.Path;
import java.util.Map;

import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public class CheckForLog4jPluginAnnotation implements Detector<Detections> {

	private static final String NAME = "jndi";
	private static final String CATEGORY = "Lookup";

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		if (hasPluginAnnotation(classNode)) {
			detections.add(this, filename);
		}
	}

	private static boolean hasPluginAnnotation(ClassNode classNode) {
		for (AnnotationNode annotationNode : nullSafety(classNode.visibleAnnotations)) {
			// TODO build a map of annotations and verify if they match the properties of
			// org.apache.logging.log4j.plugins.Plugin (TODO define which log4j version
			// Plugins included what attributes)
			if ("Lorg/apache/logging/log4j/core/config/plugins/Plugin;".equals(annotationNode.desc)) {
				Map<Object, Object> values = toMap(annotationNode, annotationNode.values);
				// @Plugin(name = "jndi", category = "Lookup")
				if (NAME.equals(values.get("name")) && CATEGORY.equals(values.get("category"))) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public String format(Detection detection) {
		return "@Plugin(name = \"" + NAME + "\", category = \"" + CATEGORY + "\")";
	}

}
