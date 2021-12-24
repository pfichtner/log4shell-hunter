package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodName;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public abstract class AbstractDetector implements Detector {

	private Stack<String> resources = new Stack<>();
	private List<Detection> detections;

	@Override
	public void visit(String resource) {
		this.detections = new ArrayList<>();
		this.resources.push(resource);
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
		this.resources.pop();
	}

	public String getResource() {
		return resources.peek();
	}

	public List<Detection> getDetections() {
		return detections;
	}

	public void addDetection(Path filename, ClassNode classNode, String description) {
		addDetection(new Detection(this, getResource(), filename, classNode, description));
	}

	public void addDetection(Detection detection) {
		detections.add(detection);
	}

	public static String referenceTo(MethodInsnNode node) {
		return "Reference to " + methodName(node);
	}

}
