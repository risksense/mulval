#!/bin/sh
# Update the local database with the up-to-date NVD data feed from NIST.
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

NVDPATH=nvd_xml_files
CLASSPATH=$CLASSPATH:$MULVALROOT/lib/dom4j-1.6.1.jar:$MULVALROOT/lib/jaxen-1.1.1.jar:$MULVALROOT/lib/mysql-connector-java-5.1.8-bin.jar:$MULVALROOT/bin/adapter
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

rm -f connectionSucc.txt

if [ ! -d $NVDPATH ]; then
    mkdir $NVDPATH
fi
cd $NVDPATH
rm -f nvdcve*
i=2002


year=`date +"%Y"`
while [ $i -le $year ]; do
      wget  http://nvd.nist.gov/download/nvdcve-$i.xml.gz
      gunzip -f nvdcve-$i.xml.gz
      i=`expr $i + 1`
done
cd ..
java -cp $CLASSPATH -Xmx512m InitializeDB $year
echo "NVD update finished. You can remove the temporary NVD files in $NVDPATH."