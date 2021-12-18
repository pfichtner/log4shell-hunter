package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodName;

import java.net.URI;
import java.nio.file.Path;

import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detections;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public abstract class AbstractDetector implements Detector {

	private Detections detections;
	private URI jar;

	@Override
	public void visit(URI jar) {
		this.jar = jar;
		this.detections = new Detections();
		Detector.super.visit(jar);
	}

	public URI getJar() {
		return jar;
	}

	public Detections getDetections() {
		return detections;
	}

	public void addDetections(Path filename, String description) {
		detections.add(this, filename, description);
	}
	
	public static String referenceTo(MethodInsnNode node) {
		return "Reference to " + methodName(node);
	}

}
