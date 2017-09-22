#!/bin/bash
#
# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

if [ ! -d clouds ]; then
    echo "Must run in the directory above cloud output"
    exit
fi


DATE=`date +"%Y-%B-%d"`
LATEST=/var/www/html/ARDANA/latest
outdir=/var/www/html/ARDANA/ARDANA-${DATE}
rm -rf $outdir
mkdir -p $outdir

index=$outdir/index.html
rm -f $index
echo "<html>" >> $index

updated=`date +"%H:%M %d %B %Y"`
echo "<h3><i>Last Updated: $updated</i></h3>" >> $index

if [[ -d coverage ]] ; then
    cd coverage
    coverage combine
    mkdir -p $outdir/coverage
    echo "<h3>Code Coverage</h3>" >> $index
    echo "<table border=1 cellpadding=10>" >> $index

    for f in validators migrators generators builders finalizers variables explainers; do
        res=`coverage report --include "*/ardana_configurationprocessor/plugins/$f*" |  tail -1 | sed -e "s/  */ /g" | cut -d" " -f4`
        coverage html --include "*/ardana_configurationprocessor/plugins/$f*" -d $outdir/coverage/$f
        echo "<tr>" >> $index
        echo "<td><a href=coverage/$f>$f</a></td>" >> $index
        echo "<td>$res</td>" >> $index
        echo "</tr>" >> $index
    done
    res=`coverage report --omit "*/ardana_configurationprocessor/plugins/*" |  tail -1 | sed -e "s/  */ /g" | cut -d" " -f4`
    coverage html --omit "*/ardana_configurationprocessor/plugins/*" -d $outdir/coverage/other
    echo "<tr>" >> $index
    echo "<td><a href=coverage/other>other</a></td>" >> $index
    echo "<td>$res</td>" >> $index
    echo "</tr>" >> $index
    echo "</table><br>" >> $index
    cd ..
fi

cd clouds
for f in *
do
    echo "<h3>$f</h3>" >> $index
    echo "<table border=1 cellpadding=10>" >> $index

    mkdir -p $outdir/$f
    for t in `find $f -path "*ref/html"`
    do
        test_name=${t%%/ref/html}
        test_name=${test_name##$f/}
        test_dir=$outdir/$f/$test_name
        echo $test_name

        rm -rf $test_dir
        mkdir -p $test_dir
        cp -r $f/$test_name/ref/html $test_dir
        cp -r $f/$test_name/ref/info $test_dir
        mkdir -p $test_dir/input_model
        cp -r ../ardana-input-model/2.0/$f/$test_name/* $test_dir/input_model

        echo "<tr>" >> $index
        echo "<td>$test_name</td>" >> $index
        echo "<td><a href=$f/$test_name/html/Control_Planes.html>html</a></td>" >> $index
        echo "<td><a href=$f/$test_name/info>info</a></td>" >> $index
        echo "<td><a href=$f/$test_name/input_model>input_model</a></td>" >> $index
        echo "</tr>" >> $index
    done
    echo "</table><br>" >> $index
done
cd ..

rm $LATEST
ln -s $outdir $LATEST
