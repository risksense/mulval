#!/bin/sh
if [ -z $1 ]; then
    echo "runRiskAssess.sh input_file [ATTCK_GRAPH OPTIONS]"
    exit 0
fi

echo "##Computing attack graph..."
echo "graph_gen.sh $1 -l $2 $3 $4 $5 $6 $7 $8 $9"
graph_gen.sh $1 --cvss -l $2 $3 $4 $5 $6 $7 $8 $9
if [ "$?" -ne "0" ]; then echo "No attack graph was generated."; exit 1; fi
echo "##Done."
echo

$MULVALROOT/utils/compute_metrics.sh $2 $3 $4 $5 $6 $7 $8 $9