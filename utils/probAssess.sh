#!/bin/sh
# This scripts invokes the risk-assessment algorithm by Wang et al.
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
CLASSPATH=$CLASSPATH:$MULVALROOT/bin/metrics

java -cp $CLASSPATH independentAlgoSumm
mv VERTICES_METRICS.CSV VERTICES.CSV
render.sh $1 $2 $3
