#!/bin/sh
# Translation from NESSUS vulnerability scan result into MulVAL input.
# Author: Su Zhang, Xinming Ou
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

export MALLOC_CHECK_=0
CLASSPATH=$CLASSPATH:$MULVALROOT/lib/dom4j-1.6.1.jar:$MULVALROOT/lib/jaxen-1.1.1.jar:$MULVALROOT/lib/mysql-connector-java-5.1.8-bin.jar:$MULVALROOT/bin/adapter
ADAPTERSRCPATH=$MULVALROOT/src/adapter

if [ ! -r config.txt ]; then
    echo "config.txt does not exist. Please refer to the README and create config.txt first."
    exit 1
fi

java -cp $CLASSPATH mysqlConnectionChecker

if [ -r connectionSucc.txt ]; then
    echo 'connection tested successfully'
else
# echo 'connection cannot be established'
 exit 1
fi

java -cp $CLASSPATH NessusXMLParser $1

if grep -qF "CVE" vulInfo.txt; then
    echo 'vulnerability(ies) detected'
else
 echo 'no vulnerability detected'
 exit 1
fi


java -cp $CLASSPATH GetTplQry_nessusXML vulInfo.txt

xsb_logfile="xsb_nessus_translate.log"
xsb 2>$xsb_logfile 1>&2 <<EOF
[results].
['$MULVALROOT/lib/libmulval'].
['$ADAPTERSRCPATH/nessus_translator'].
tell('nessus.P').
findall(vulProperty(A,B,C),vulProperty(A,B,C),L),list_apply(L,write_clause_to_stdout).

%findall(remote_client_vul_exists(A,B),remote_client_vul_exists(A,B),L),list_apply(L,write_clause_to_stdout).

findall(vulExists(A,B,C),vulExists(A,B,C),L),list_apply(L,write_clause_to_stdout).

findall(cvss(CVE, AC),cvss(CVE, AC),L),list_apply(L,write_clause_to_stdout).

findall(networkServiceInfo(Host, Program, Protocol, Port, someUser), networkServiceInfo(Host, Program, Protocol, Port, someUser), L), list_apply(L,write_clause_to_stdout).

%findall(hacl(Host, Host1, Protocol, Port), hacl(Host, Host1, Protocol, Port), L), list_apply(L,write_clause_to_stdout).

told.
halt.
EOF

if [ ! -e nessus.P ]; then
    echo "Error in translating NESSUS scan results. Please refer to $xsb_logfile."
    exit 1
fi

cat accountinfo.P >> nessus.P
echo "hacl(_,_,_,_).">>nessus.P
#cat $ADAPTERSRCPATH/client_software.P>> nessus.P
echo "Output can be found in nessus.P."

#java -cp $CLASSPATH XMLConstructor
#echo "An XML format of attackGraph could be found at XMLGraph.xml"
# Perform summarization
nessus_vul_summary.sh nessus.P
cat accountinfo.P >>summ_nessus.P
echo "hacl(_,_,_,_).">>summ_nessus.P
#cat $ADAPTERSRCPATH/client_software.P >> summ_nessus.P
