package com.github.pfichtner.log4shell.scanner.detectors;

import static java.util.Spliterator.ORDERED;
import static java.util.Spliterators.spliteratorUnknownSize;

import java.util.Iterator;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public final class Streams {

	private Streams() {
		super();
	}

	public static <T> Stream<T> itToStream(Iterator<T> sourceIterator) {
		return StreamSupport.stream(spliteratorUnknownSize(sourceIterator, ORDERED), false);
	}

	public static <T> Stream<T> filter(Stream<? super T> instructions, Class<T> type) {
		return instructions.filter(type::isInstance).map(type::cast);
	}

}
