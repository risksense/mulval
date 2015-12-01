#!/bin/sh
# This scripts invokes xsb for summarization.
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

if [ -z $1 ]; then
    echo "Usage summary.sh input_file"
    exit 0
fi

if [ -z "$MULVALROOT" ]; then
    echo '$MULVALROOT environment variable not set.'
    exit -1
fi

vulnFile=$1
summfile="summ_$vulnFile"
grpfile="grps_$vulnFile"
logfile="xsb_vul_summary.log"

xsb 2> $logfile 1>&2 <<EOF
['$MULVALROOT/lib/libmulval.P'].
['$MULVALROOT/src/analyzer/auxiliary.P'].
['$MULVALROOT/src/adapter/vul_summary.P'].

load_dyn('$vulnFile').

tell('$summfile').

summarize_vuln('$grpfile').

findall(networkServiceInfo(Host, Program, Protocol, Port, someUser), networkServiceInfo(Host, Program, Protocol, Port, someUser), L), list_apply(L,write_clause_to_stdout).

findall(hacl(Host, Host1, Protocol, Port), hacl(Host, Host1, Protocol, Port), L), list_apply(L,write_clause_to_stdout).

findall(hasAccount(A,B,C), hasAccount(A,B,C), L), list_apply(L,write_clause_to_stdout).

findall(inCompetent(A), inCompetent(A), L), list_apply(L,write_clause_to_stdout).

findall(attackGoal(A), attackGoal(A), L), list_apply(L,write_clause_to_stdout).

findall(attackerLocated(A), attackerLocated(A), L), list_apply(L,write_clause_to_stdout).

told.

EOF

if [ ! -s $summfile ] || [ ! -s $grpfile ]; then
    echo "Error in summarization. Please look into $logfile."
#    rm $summfile $mapfile
    exit 1
fi

echo "Summarized vulnerability information can be found in $summfile and $grpfile."