package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodName;

import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public abstract class AbstractDetector implements Detector {

	private List<Detection> detections;
	private URI jar;

	@Override
	public void visit(URI jar) {
		this.jar = jar;
		this.detections = new ArrayList<>();
		Detector.super.visit(jar);
	}

	public URI getJar() {
		return jar;
	}

	public List<Detection> getDetections() {
		return detections;
	}

	public void addDetections(Path filename, String description) {
		detections.add(new Detection(this, filename, description));
	}

	public static String referenceTo(MethodInsnNode node) {
		return "Reference to " + methodName(node);
	}

}
