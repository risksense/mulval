default: install

attack_graph: attack_graph.cpp attack_graph.h Queue.h lex.yy.o y.tab.cpp
	g++ -g -DLINUX -Wno-deprecated lex.yy.o y.tab.cpp attack_graph.cpp -o attack_graph

lex.yy.c: graphit.l
	lex  -olex.yy.c graphit.l 

lex.yy.o: lex.yy.c y.tab.cpp.h
	gcc -g -c lex.yy.c -o lex.yy.o

y.tab.cpp y.tab.cpp.h: graphit.y attack_graph.h 
	bison -dv graphit.y
	mv graphit.tab.c y.tab.cpp
	mv graphit.tab.h y.tab.cpp.h

install: attack_graph
	cp attack_graph ../../bin/

clean:
	rm -f y.tab.cpp y.tab.cpp.h lex.yy.c *.o attack_graph *.output
