#!/bin/sh
# Author: Xinming Ou
# Kansas State University
# Date: Dec 3, 2011
# 
# This scripts performs risk-assessment over the attack-graph based on John Homer's algorithm.

echo "##Running risk assessment algorithm..."
$MULVALROOT/utils/risk_assessment.py > assessed.P
echo "##Done."
echo
echo "##Parsing the results..."
java -cp $MULVALROOT/bin/adapter MetricParser
echo "##Done."
echo
echo "##Rendering the results..."
sort -n riskassessment.txt > VERTICES.CSV
render.sh $1 $2 $3 $4 $5 $6 $7 $8
#rm riskassessment.txt
#rm assessed.P