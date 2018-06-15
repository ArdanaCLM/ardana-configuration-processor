#!/bin/bash -e
#
# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017-2018 SUSE LLC
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

script_path="$(readlink -e "${0}")"
scripts_dir="$(dirname "${script_path}")"
acp_base="$(dirname "${scripts_dir}")"
clone_base="$(dirname "${acp_base}")"
#venv_dir="${acp_base}/.venvs/acp"

help ()
{
  echo "-g | --<git_base>         Git base to use (default: $git_base)"
  echo "-b | --branch <branch>    Git branch to use for a-c-p-repo (default: $branch)"
  echo "-m | --m-branch <branch>  Git branch to use for a-i-m repo (default: $m_branch)"
  echo "-r | --r-branch <branch>  Git branch to use for a-i-m-r repo (default: $r_branch)"
  echo "-d | --d-branch <branch>  Git branch to use for ardana dcn repo (default: $d_branch)"
  echo "-o | --o-branch <branch>  Git branch to use for ardana odl repo (default: $o_branch)"
  echo "-n | --no-ref             Don't create reference"
  echo "-p | --pull               Clone repos even if the already exist"
  echo "-x | --no-reset           Do not reset head for locally cloned repos"
}

OPTS=$(getopt -o g:b:m:r:d:o:hnpx --long git_base,branch,m-branch,r-branch,d-branch,o-branch,help,no-ref,pull,no-reset -n 'parse-options' -- "$@")
eval set -- "$OPTS"

if [ $? != 0 ] ; then echo "Failed parsing options." >&2 ; exit 1 ; fi

show_help=false
branch="master"
r_branch="master"
m_branch="master"
d_branch="master"
o_branch="master"
git_base="git://git.suse.provo.cloud"
git_namespace="ardana"
cp_opts=
build_ref=true
fresh_clone=false
reset_head=false

while true; do
  case $1 in
    -g | --git-base) shift; git_base=$1; shift;;
    -b | --branch) shift; branch=$1; shift ;;
    -m | --m-branch) shift; m_branch=$1; shift ;;
    -r | --r-branch) shift; r_branch=$1; shift ;;
    -d | --d-branch) shift; d_branch=$1; shift ;;
    -o | --o-branch) shift; o_branch=$1; shift ;;
    -h | --help) show_help=true; shift ;;
    -n | --no-ref) build_ref=false; shift ;;
    -p | --pull) fresh_clone=true; shift ;;
    -x | --no-reset) reset_head=false; shift ;;
    -- ) shift; break ;;
    *) break;;
  esac
done


if $show_help; then
  help
  exit
fi

if [ -d $1 ]; then
  echo "$1 already exists"
  exit 1
fi

#if [ ! -d "${venv_dir}" ]; then
#    mkdir -p "$(basename "${venv_dir}")"
#    virtualenv "${venv_dir}"
#fi

#if [ ! -e "${venv_dir}/bin/activate" ]
#then
#    echo "Python venv '${venv_dir}' not setup correctly"
#    exit 1
#fi

#. "${venv_dir}/bin/activate"

#if pip freeze -l -r ConfigurationProcessor/requirements.txt 2>&1 | \
#    grep -qs "package is not installed"; then
#    pip install -r "${acp_base}/ConfigurationProcessor/requirements.txt"
#fi
#
#if ! pip freeze -l | grep -qs "^ansible=="; then
#    pip install ansible
#fi

echo using branch $branch
echo using external branch $external_branch
echo using ardana-input-model branch $m_branch
echo using ardana-input-model-ref branch $r_branch
echo using ardana-extension-odl branch $o_branch
echo using ardana-extension-dcn branch $d_branch

target=$1
mkdir $target
cd $target

work_dir=$(pwd)

clone_repo_into_dir()
{
    local repo="${1}" branch="${2}" dest_dir="${3}"
    local repo_name="$(basename "${repo}")"

    if [[ -d "${clone_base}/${repo_name}" && $fresh_clone = "false" ]]
    then
        # copy the repo and, if reset_head is true, clear
        # out any local uncommitted changes
        cp -a "${clone_base}/${repo_name}" .
        if [[ $reset_head = "true" ]]
        then
            (
                cd ${repo_name}
                git reset --hard
                git clean -x -d -f -f
            )
        fi
    else
        git clone -b "${branch}" "${git_base}/${repo}" "${dest_dir}"
    fi
}

cd $work_dir

#
# Clone the a-i-m repo
#
clone_repo_into_dir ${git_namespace}/ardana-input-model ${m_branch} ardana-input-model

#
# Clone the a-i-m-ref repo
#
clone_repo_into_dir ${git_namespace}/ardana-input-model-ref ${r_branch} ardana-input-model-ref

#
# Clone the extensions repos
#
clone_repo_into_dir ardana/ardana-extensions-dcn ${d_branch} ardana-extensions-dcn
clone_repo_into_dir ardana/ardana-extensions-odl ${o_branch} ardana-extensions-odl

# Look for any additional service definitons and copy them into
# the input model directory so they get picked up.   Make sure that
# git ignores this temporary directory
mkdir ardana-input-model/2.0/services/.extensions
echo "*" > ardana-input-model/2.0/services/.extensions/.gitignore
for dir in $(find . -name "ardana-extensions-*"); do
    for service_dir in $(find $dir -name "services" -type d); do
        echo "Adding additional services from $service_dir"
        cp -r $service_dir/* ardana-input-model/2.0/services/.extensions
    done
done

#
# Run all of the models and generate reference outputs
#
if $build_ref; then
    cd $acp_base
    ${scripts_dir}/run_cp.sh -a -t $target
fi

# Create links to the models not in a-i-m
cd $work_dir/ardana-input-model/2.0
ln -s $work_dir/ardana-input-model-ref ref
ln -s $acp_base/Tests tests
