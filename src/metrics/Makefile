TARGET=independentAlgoSumm.class node.class

.SUFFIXES: .java .class

default: ${TARGET}

.java.class:
	javac $*.java 

install: ${TARGET}
	cp ${TARGET} ../../bin/metrics

clean:
	rm -f *.class
