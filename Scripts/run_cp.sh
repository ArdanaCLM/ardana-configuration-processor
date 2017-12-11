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

runcp ()
{
  cloud=$1
  cloudDir="$target/ardana-input-model/2.0/$cloud"
  outDir="$target/clouds/$cloud"
  coverageOutDir="$target/coverage"
  cloudConfig="$cloudDir/cloudConfig.yml"

  if [ ! -f $cloudConfig ]; then
    echo
    echo "Can't find cloud config file $cloudConfig"
    exit 1
  fi

  if $patch_ext_name; then
    cd $cloudDir/data
    if [ -f network_groups.yml ] ; then
      sed -i "s/external-name/#PHILexternal-name/" network_groups.yml
    fi
    cd $startDir
  fi


  mkdir -p $outDir
  touch $outDir/.gitignore

  # Rebuild
  cd ConfigurationProcessor
  python setup.py install > $outDir/cp_build.log

  cd $startDir

  # Clean up any cruft left around
  rm -rf persistent_state
  rm -rf stage

  # Copy the previous persistent_state
  if $use_persistent_state; then
    if  [ -d $outDir/persistent_state ]
    then
      cp -r $outDir/persistent_state .
    elif [ -d $cloudDir/../persistent_state ]
    then
      echo "Copy state from test case"
      cp -r $cloudDir/../persistent_state .
    fi
  fi

  # If any extra CP options are defined used them
  cp_extra_opts=""
  if [ -f $cloudDir/cp_opts.existing_state ]
  then
    cp_extra_opts=$(cat $cloudDir/cp_opts.existing_state)
  elif [ -f $cloudDir/cp_opts.no_state ]
  then
    cp_extra_opts=$(cat $cloudDir/cp_opts.no_state)
  fi

  rm -rf logs
  mkdir logs
  echo ardana-cp -l logs -s $target/ardana-input-model/2.0/ -c $cloudConfig -r Data/Site -w $cp_opts $cp_extra_opts
  if $run_coverage; then
      cd $startDir/Driver
      coverage run ardana-cp -l logs -s $target/ardana-input-model/2.0/ -c $cloudConfig -r Data/Site -w $cp_opts $cp_extra_opts
  else
      python Driver/ardana-cp -l logs -s $target/ardana-input-model/2.0/ -c $cloudConfig -r Data/Site -w $cp_opts $cp_extra_opts
  fi

  cpRes=$?
  test_name=$(echo $1 | sed -e "s/\//_/g")

  # Save the coveage results
  if $run_coverage; then
    mkdir -p $coverageOutDir
    mv .coverage $coverageOutDir/.coverage.$test_name
  fi

  if $patch_ext_name; then
    cd $cloudDir/data
    if [ -f network_groups.yml ]; then
        sed -i "s/#PHILexternal-name/external-name/" network_groups.yml
    fi
    cd $startDir
  fi

  err_file=$(dirname $cloudConfig)/../ref/errors
  if [ -f $err_file ]; then
      # Strip out anything except the error strings
      sed -i -e "s/.*#/#/" -e "/^[0-9]/d" -e "s/ *$//" logs/errors.log
      # Sort the two error files, and the order from the CP is non deterministic
      sort logs/errors.log >  logs/errors.log.sorted
      sort $err_file > logs/ref_errors.sorted
      diff -q logs/ref_errors.sorted logs/errors.log.sorted
      if [[ $? != 0 ]]; then
        echo
        echo "   **********************************************"
        echo "   *                                            *"
        echo "   *  Test failed: Expected errors don't match  *"
        echo "   *    < expected                              *"
        echo "   *    > actual                                *"
        echo "   *                                            *"
        echo "   **********************************************"
        echo
        diff logs/ref_errors.sorted logs/errors.log.sorted
     else
        echo
        echo "   **********************************************"
        echo "   *                                            *"
        echo "   *  Test passed: Got Expected errors          *"
        echo "   *                                            *"
        echo "   **********************************************"
        echo
        return 0
     fi
   fi

  if [ $cpRes != 0 ]; then
    echo; echo; echo
    echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo "++    CP Failed: $1"
    echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    if [ -d stage ]; then
      rm -rf $outDir/stage.failed
      mv stage $outDir/stage.failed
    fi
    return 2
  fi

  # CP passed, so save the state and compare the outputs
  if $commit_state; then
    rm -rf $outDir/persistent_state
    mv persistent_state $outDir
  else
    rm -rf $outDir/not_saved_persistent_state
    mv persistent_state $outDir/not_saved_persistent_state
  fi

  if $create_ref; then
    rm -rf $outDir/ref
    mv stage $outDir/ref
  else
    rm -rf $outDir/stage
    mv stage $outDir


    if [ -d $outDir/ref ]; then
      echo
      echo "--------------------------- Diff Summary ---------------------------"
      cd $outDir
      diff -rq ref/ansible stage/ansible
      diff -rq ref/net stage/net

      for f in server_info.yml address_info.yml
      do
         echo
         echo "................. $f .........................."
         echo
         diff -dy --suppress-common-lines ref/info/$f stage/info/$f
      done

      if $full_diff; then
        for f in $(find ref/ansible -type f -print)
        do
           echo
           echo "................. $f .........................."
           echo
           diff -dy --suppress-common-lines $f stage/${f##ref/}
        done

        for f in $(find ref/net -type f -print)
        do
           echo
           echo "................. $f .........................."
           echo
           diff -dy --suppress-common-lines $f stage/${f##ref/}
        done

        for f in $(find ref/info -name "*.yml" -type f -print)
        do
           echo
           echo "................. $f .........................."
           echo
           diff -dy --suppress-common-lines $f stage/${f##ref/}
        done

        for f in $(find ref/info/cert_reqs -type f -print)
        do
           echo
           echo "................. $f .........................."
           echo
           diff -dy --suppress-common-lines $f stage/${f##ref/}
        done

      fi
    else
      echo "No reference"
    fi
  fi

  return 0
}

declare -a OPTIONS
OPTIONS[1]="-a,run_all                   ,Run all models"
OPTIONS[2]="-c,commit                    ,Update persisted state"
OPTIONS[3]="-C,create_ref                ,Save stage output as ref"
OPTIONS[4]="-d,remove_deleted_servers    ,Remove deleted servers from persisted state"
OPTIONS[5]="-e,enrcypt                   ,Encrypt ansible vars"
OPTIONS[6]="-f,free_unused_addresses     ,Remove unused addresses from persisted state"
OPTIONS[7]="-h,help                      ,Help"
OPTIONS[8]="-i,ignore_persisted_state    ,Don't use persisted state"
OPTIONS[9]="-I:,include:                 ,Add extra models r (ref) t (test) h (CI) a(all)"
OPTIONS[10]="-k,change_key               ,Change encryption key"
OPTIONS[11]="-N,non_interactive          ,Run all models specified with -I option"
OPTIONS[12]="-p,refresh_all_secrets      ,Refresh all secrets"
OPTIONS[13]="-P:,credential_change_path: ,Credential Change Path"
OPTIONS[14]="-q,quiet                    ,Only show CP result"
OPTIONS[15]="-t:,target:                 ,Target directory containing the models"
OPTIONS[16]="-v,verbose_diff             ,Show differences in generated ansible"
OPTIONS[17]="-x,leave_ext_name           ,Don't edit external name in network groups"
OPTIONS[18]="-y,coverage                 ,Run with code coverage"
OPTIONS[19]="-z,repeat                   ,Run with last selected model"

ol=""
olong=""
for o in "${OPTIONS[@]}"; do
  x=${o%%,*}
  ol=$ol${x#-}

  if [ ! -z "$olong" ]; then
    olong="$olong,"
  fi
  l=${o#*,}
  olong=$olong${l%% *}
done


help ()
{
  for o in "${OPTIONS[@]}"; do
    x=${o%%,*}
    l=${o#*,}
    t=${o##*,}
    printf "%-4s %-30s %s\n" ${x} --${l%%,*} "${t}"
  done
}


OPTS=$(getopt -o $ol --long $olong -n 'parse-options' -- "$@")
#OPTS=$(getopt -o qarekdfvxcipP:I:t:Nhz --long quiet,run_all,create_ref,encrypt,change_key,remove_deleted_servers,free_unused_addresses,verbose_diff,leave_ext_name,commit,ignore_persisent_state,refresh_all_secrets,credential_change_path:,include:,target:,non_interactive,help -n 'parse-options' -- "$@")
eval set -- "$OPTS"

if [ $? != 0 ] ; then echo "Failed parsing options." >&2 ; exit 1 ; fi

startDir=$(pwd)
target=$(pwd)
create_ref=false
full_diff=false
patch_ext_name=true
commit_state=false
run_all=false
run_coverage=false
quiet=false
include_ref=false
include_test=false
include_ci=false
include=""
use_persistent_state=true
show_help=false
non_interactive=false
cp_opts=
last_run_file="../../last_run"

while true; do
  case $1 in
    -a | --run-all) run_all=true; shift ;;
    -c | --commit) commit_state=true; shift ;;
    -C | --create_ref) create_ref=true; commit_state=true; shift ;;
    -d | --remove_deleted_servers) cp_opts="$cp_opts -d"; shift ;;
    -e | --encrypt) cp_opts="$cp_opts -e -q -x MyTestKey001"; shift ;;
    -f | --free_unused_addresses) cp_opts="$cp_opts -f"; shift ;;
    -h | --help) show_help=true; shift ;;
    -i | --ignore_persistent_state) use_persistent_state=false; shift ;;
    -I | --include) include="$include $2"; shift 2;;
    -k | --change_key) cp_opts="$cp_opts -k"; shift ;;
    -N | --non_interactive) non_interactive=true; shift ;;
    -p | --refresh_all_secrets) cp_opts="$cp_opts -p"; shift ;;
    -P | --credential_change_path) cp_opts="$cp_opts -P $2"; shift 2;;
    -q | --quiet) quiet=true; shift ;;
    -t | --target) target="$target/$2"; shift 2;;
    -v | --verbose_diff) full_diff=true; shift ;;
    -x | --leave_ext_name) patch_ext_name=false; shift ;;
    -y | --coverage) run_coverage=true; shift ;;
    -z | --repeate) clouds=$(cat $last_run_file); shift ;;
    -- ) shift; break ;;
    *) break;;
  esac
done

echo "The working directory for processing is" $target

if $show_help; then
  help
  exit
fi

default="No Default"
if [ -f $last_run_file ]; then
  default=$(cat $last_run_file)
fi

for inc in $include; do
  case $inc in
    r) include_ref=true ;;
    t) include_test=true ;;
    h) include_ci=true ;;
    a) include_ref=true; include_test=true; include_ci=true;;
    *) echo "unknown include code: $inc"; exit ;;
  esac
done

if $include_ref; then
   strip_ref=""
else
   strip_ref='-e /^ref/d'
fi

if $include_test; then
   strip_test=""
else
   strip_test='-e /^test/d'
fi

if $include_ci; then
   strip_ci=""
else
   strip_ci='-e /^ardana-ci/d'
fi

if [ $# -lt 1 ]; then
  cd $target/ardana-input-model/2.0
  models=$(find -L . -name "cloudConfig.yml" | sed -e "s/^.\///" ${strip_ref} ${strip_test} ${strip_ci}  -e "s/\/cloudConfig.yml//" | sort)
  cd $startDir
  if $run_all; then
    clouds=$models
  elif [ $non_interactive = true ]; then
    clouds=$models
  elif [ -z $clouds ]; then
    select clouds in "$default" $models; do
      break
    done
    echo $clouds > $last_run_file
  fi
else
  clouds=$*
fi

passed=""
failed=""
for cloud in $clouds; do
  cd $startDir
  echo
  echo "***************** $cloud *********************"
  echo
  if $quiet; then
    runcp $cloud > /tmp/cp.out
    result=$?
    grep -B1 -A100 "The configuration processor" /tmp/cp.out
  else
    runcp $cloud
    result=$?
  fi
  if [ $result == 0 ]; then
    passed="${passed}Passed: ${cloud} \n"
  else
    failed="${failed}FAILED: ${cloud} \n"
  fi
  pwd
done

echo -e ${passed}
echo
echo -e ${failed}
echo
