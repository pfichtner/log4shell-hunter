package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.initialContextLookup;
import static com.github.pfichtner.log4shell.scanner.detectors.LookupConstants.methodNameIsLookup;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodInsnNodes;
import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodName;

import java.nio.file.Path;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public class CheckForRefsToInitialContextLookups implements Detector<Detections> {

	@Override
	public void visitClass(Detections detections, Path filename, ClassNode classNode) {
		// TODO should be distinctBy target
		methodInsnNodes(classNode, methodNameIsLookup).filter(initialContextLookup).distinct()
				.forEach(n -> detections.add(this, filename, n));
	}

	@Override
	public String format(Detection detection) {
		return "Reference to " + methodName((MethodInsnNode) detection.getObject());
	}

}
