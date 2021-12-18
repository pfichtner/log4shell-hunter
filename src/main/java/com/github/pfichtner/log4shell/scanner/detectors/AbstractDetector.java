package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodName;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.CVEDetector.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public abstract class AbstractDetector implements Detector {

	private List<Detection> detections;
	private String resource;

	@Override
	public void visit(String resource) {
		this.resource = resource;
		this.detections = new ArrayList<>();
	}

	@Override
	public void visitClass(Path filename, ClassNode classNode) {
		// noop
	}

	@Override
	public void visitFile(Path file, byte[] bytes) {
		// noop
	}

	@Override
	public void visitEnd() {
		// noop
	}

	public String getResource() {
		return resource;
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
