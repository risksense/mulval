default: all

all: adapter attack_graph metrics

adapter:
	(cd src/adapter; make; make install)

attack_graph:
	(cd src/attack_graph; make install)

metrics:
	(cd src/metrics; make; make install)

clean:
	(cd src/attack_graph; make clean)
	(cd src/adapter; make clean)
	(cd src/metrics; make clean)
