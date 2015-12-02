#!/bin/sh
# Generate a MulVAL attack graph
# Author: Xinming Ou
# Copyright (C) 2011, Argus Cybersecurity Lab, Kansas State University

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

INTERACTIONRULES=$MULVALROOT/kb/interaction_rules.P
INTERACTIONRULES_CVSS=$MULVALROOT/kb/interaction_rules_with_metrics.P
RULES_WITH_METRIC_ARTIFACTS=$MULVALROOT/kb/interaction_rules_with_metric_artifacts.P
rule_file=$INTERACTIONRULES

trace_option=completeTrace2

if [ ! -x $MULVALROOT/bin/attack_graph ]; then
    echo "The attack-graph generator has not been compiled, or the MULVALROOT environment variable is not set appropriately!"
    exit 1;
fi

ac_prev=
for ac_option
do
  # If the previous option needs an argument, assign it.
  if test -n "$ac_prev"; then
    eval "$ac_prev=\$ac_option"
    ac_prev=
    continue
  fi

  case "$ac_option" in
      -r | --rulefile)
      ac_prev=rule_file ;;

      -a | --additional)
      ac_prev=additional_rule_file ;;

      -c | --constraint)
      ac_prev=constraint_file ;;

      -g | --goal)
      ac_prev=goal ;;

      -d | --dynamic)
      ac_prev=dynamic_file ;;

      -v | --visualize)
      VISUALIZE=true
      CSVOutput=true;;

      -l)
      CSVOutput=true;;

      --arclabel | --reverse | --simple | --nometric | --nopdf)
      VISUALIZATION_OPTS="$VISUALIZATION_OPTS $ac_option" ;;

      -s | --sat)
      SAT=true ;;

      -sg | --satgui)
      SATGUI=true ;;

      -t | --trace)
      ac_prev=trace_option ;;

      -tr | --trim)
      TRIM=true ;;

      -td | --trimdom)
      TRIMDOM=true ;;

      --cvss)
      CVSS=true 
      rule_file=$INTERACTIONRULES_CVSS ;;

      -ma)
      if test -z "$CVSS"; then
	  CVSS=true
      fi
      rule_file=$RULES_WITH_METRIC_ARTIFACTS ;;

      -h | --help)
      cat <<EOF
Usage: graph_gen.sh [-r|--rule rulefile]
                    [-a|--additional additional_rulefile]
		    [-c|--constraint constraint_file]
		    [-g|--goal goal]
		    [-d|--dynamic dynamic_file]
		    [-p]
		    [-s|--sat]
		    [-t|--t trace_option]
		    [-tr|--trim]
		    [-v|--visualize [--arclabel] [--reverse] [--nopdf]]
                    [--cvss]
	            [-h|--help]
	            [attack_graph_options]
	            input_file
EOF
      exit ;;

      #unrecognized options will be passed to attack graph generator
      -*) 
      ATTACK_GRAPH_OPTS="$ATTACK_GRAPH_OPTS $ac_option" ;;

      *)
      if test -n "$INPUT"
      then 
	  echo "Incorrect command-line option for graph_gen.sh: $ac_option" >&2
	  exit 2
      else 
	  INPUT=$ac_option
      fi
  esac
done

if ! test -n "$INPUT"
then
    echo "What is the input file?" >&2
    exit 2
fi

if ! test -e "$INPUT"
then
    echo "File $INPUT does not exist." >&2
    exit 2
fi

#If using graphViz, need to dump the arcs and vertices into a temporary file.
if test -n "$CSVOutput"
then
    ATTACK_GRAPH_OPTS="-l $ATTACK_GRAPH_OPTS"
fi

if test -n "$SAT"
then
    ATTACK_GRAPH_OPTS="-s $ATTACK_GRAPH_OPTS"
fi    

#DEBUG=true
if test -n "$DEBUG"
then
    echo "MULVALROOT is: " $MULVALROOT
    echo "rule file is:"
    echo "$rule_file"
    echo "constraint file is:"
    echo "$constraint_file"
    echo "additional rule file is:"
    echo "$additional_rule_file"
    echo "attack graph options are:"
    echo "$ATTACK_GRAPH_OPTS"
    echo "input file is:"
    echo "$INPUT"
    echo "goal is:"
    echo "$goal"
    echo "dynamic changes file is:"
    echo "$dynamic_file"
    echo "Attack Graph opts is $ATTACK_GRAPH_OPTS"
fi

rm -f trace_output.P
rm -f xsb_log.txt

cat $rule_file $additional_rule_file > running_rules.P

# create an XSB running script
cat > run.P <<EOF
:-['$MULVALROOT/lib/libmulval'].
:-['$MULVALROOT/src/analyzer/translate'].
:-['$MULVALROOT/src/analyzer/attack_trace'].
:-['$MULVALROOT/src/analyzer/auxiliary'].

:-dynamic meta/1.

:-load_dyn('running_rules.P').

:-load_dyn('$INPUT').

:-assert(traceMode($trace_option)).

EOF

if test -n "$dynamic_file"; then
    cat >> run.P <<EOF
:-load_dyn('$dynamic_file').

:-apply_dynamic_changes.

EOF
fi

if test -n "$TRIM"; then
    cat >> run.P <<EOF
:-load_dyn('$MULVALROOT/src/analyzer/advances_trim.P').

:-tell('edges').

:-writeEdges.

:-told.

:-shell('rm -f dominators.P').

:-shell('dom.py edges dominators.P').

:-loadDominators('dominators.P').

EOF
else
    cat >> run.P <<EOF
:-load_dyn('$MULVALROOT/src/analyzer/advances_notrim.P').

EOF
fi

if test -z "$CVSS"; then
    cat >> run.P <<EOF
:-assert(cvss(_, none)).

EOF
fi

if test -n "$goal"; then

cat >> run.P <<EOF
:- assert(attackGoal($goal)).

EOF
fi

cat run.P > environment.P

xsb 2>xsb_log.txt 1>&2 <<EOF
[environment].
tell('goals.txt').
writeln('Goal:').
iterate(attackGoal(G),
        (write(' '), write_canonical(G), nl)).
told.
EOF

cat goals.txt; rm goals.txt

cat >> run.P <<EOF
:-mulval_run.

EOF

# executing the running script in XSB
xsb 2>xsb_log.txt 1>&2 <<EOF
[run].

EOF

if [ -f trace_output.P ]; then
    if [ -f metric.P ]; then
	cat metric.P >> trace_output.P
    fi
    $MULVALROOT/bin/attack_graph $ATTACK_GRAPH_OPTS trace_output.P > AttackGraph.txt
    if [ "$?" -ne "0" ]; then exit 1; fi

    if test -n "$CSVOutput"
    then
	grep -E "AND|OR|LEAF" AttackGraph.txt > VERTICES.CSV
	grep -Ev "AND|OR|LEAF" AttackGraph.txt > ARCS.CSV
	if test -n "$TRIMDOM" ; then
            trim.py
	fi
    fi
    if test -n "$VISUALIZE"; then
	render.sh $VISUALIZATION_OPTS
    else
	echo "The attack graph data can be found in AttackGraph.txt."
    fi
    if test -n "$SATGUI"; then
	$MULVALROOT/utils/load_policy.sh 
    fi
else
    echo "The attack simulation encountered an error."
    echo "Please check xsb_log.txt."
    exit 2
fi

if [ -r VERTICES.CSV ] && [ -r  ARCS.CSV ]; then

    CLASSPATH=$CLASSPATH:$MULVALROOT/bin/adapter
    java -cp $CLASSPATH XMLConstructor
else
 exit 1
fi

