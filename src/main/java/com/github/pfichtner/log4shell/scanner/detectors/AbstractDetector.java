package com.github.pfichtner.log4shell.scanner.detectors;

import static com.github.pfichtner.log4shell.scanner.util.AsmUtil.methodName;
import static java.util.stream.Collectors.joining;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;
import java.util.stream.Collectors;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;

import com.github.pfichtner.log4shell.scanner.DetectionCollector.Detection;
import com.github.pfichtner.log4shell.scanner.io.Detector;

public abstract class AbstractDetector implements Detector {

	private final Stack<String> resources = new Stack<>();
	private List<Detection> detections;

	@Override
	public void visit(String resource) {
		detections = new ArrayList<>();
		resources.push(resource);
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
		resources.pop();
	}

	public String getResource() {
		return resources.stream().collect(joining("$"));
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
