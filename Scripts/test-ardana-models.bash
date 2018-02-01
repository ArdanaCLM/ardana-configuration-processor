#!/bin/bash
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
TOPDIR="${WORKSPACE:-${PWD}}"

run_tox()
{
  (
    cd ardana-configuration-processor
    tox ${PYPI_MIRROR:+-i ${PYPI_MIRROR}} -e venv -- \
        python \
            Driver/ardana-cp -w\
            -c "../${conf}" \
            -r Data/Site \
            -s "${TOPDIR}/ardana-input-model/2.0/services" \
            -l "${TESTRUNSDIR}/${testname}/ardana_logs" \
            -o "${TESTRUNSDIR}/${testname}/output" ${CP_OPTS}
    return $?
  )
}

output_testname_tmpl="

 --------------------------------------------------------------------------
|                                                                          |
| Testing: \$(printf \"%-64s|\" \${testname})
|                                                                          |
 --------------------------------------------------------------------------

"

add_summary()
{
    # Add a summary of the result
    #   $1 - test source
    #   $2 - test name
    #   $3 - result of CP run
    #   $4 - errors expected
    #   $5 - errors matched
    #   $6 - dir to wite status to

    if [[ $3 == 0 ]]; then
        mkdir -p $6/$1
        echo $2 >> $6/$1/passed
    else
        if [[ $4 == true ]]; then
            if [[ $5 == true ]]; then
                mkdir -p $6/$1
                echo $2 >> $6/$1/passed_with_errors
             else
                mkdir -p $6/$1
                echo $2 >> $6/$1/failed_with_errors
             fi
        else
            mkdir -p $6/$1
            echo $2 >> $6/$1/failed
        fi
    fi
}

print_summary()
{
        results=`find ${1} -name passed`
        if [[ ${results} ]]; then
            echo "Passed:"
            for t in ${results}; do
                test=${t##$1/}
                test=${test%%/passed}
                echo "  $test"
                cat ${t} | sed -e "s/^/    /"
            done
            echo
        fi

        results=`find ${1} -name passed_with_errors`
        if [[ ${results} ]]; then
            echo "Passed with expected errors:"
            for t in ${results}; do
                test=${t##$1/}
                test=${test%%/passed_with_errors}
                echo "  $test"
                cat ${t} | sed -e "s/^/    /"
            done
            echo
        fi

        results=`find ${1} -name failed_with_errors`
        if [[ ${results} ]]; then
            echo "Failed with mis-matched errors:"
            for t in ${results}; do
                test=${t##$1/}
                test=${test%%/failed_with_errors}
                echo "  $test"
                cat ${t} | sed -e "s/^/    /"
            done
            echo
        fi

        results=`find ${1} -name failed`
        if [[ ${results} ]]; then
            echo "Failed:"
            for t in ${results}; do
                test=${t##$1/}
                test=${test%%/failed}
                echo "  $test"
                cat ${t} | sed -e "s/^/    /"
            done
            echo
        fi
    echo
}

run_tests()
{
    # Find all the models we have to tests
    CONFIGS="$(find $1 -name cloudConfig.yml)"

    for conf in ${CONFIGS}; do

        # Extract the name of this config from the path to its cloudConfig
        #
        # First strip of the path we were give to the set of test cases
        testname=${conf##${1}}
        testname=${testname##/}

        # ... then take of the config file name
        testname=${testname%%/cloudConfig.yml}

        # ... test cases have thier input model in a model dir
        testname=${testname%%model}
        testname=${testname##/}

        # Check if there is persistent_state for this testcase
        if [[ -d $1/${testname}/persistent_state ]]; then
            STATE="$1/${testname}/persistent_state"
            STATE_TYPE="existing_state"
        else
            STATE=""
            STATE_TYPE="no_state"
        fi

        # If were given the full path to the test then we don't
        # have anything left in testname
        if [[ -z ${testname} ]]; then
            testname=$(basename ${1})
        fi

        # See if have expected errors
        if [[ -f $(dirname $conf)/../ref/errors ]]; then
           can_fail=true
        else
           can_fail=false
        fi

        # Print a pretty banner
        eval echo -e \""${output_testname_tmpl}"\"

        # patch cloud config to ignore empty external name
        network_groups_file=$(find ${conf%/*} -name network_groups.yml)
        if [[ -e ${network_groups_file} ]] ; then
            echo "Patching network_groups.yml for ${testname} to ignore blank"
            echo "external name which must be provided by customers"
            sed -i -e '/external-name/ s/^#*/#/' ${network_groups_file}
        fi

        # Create a directory for the logs
        mkdir -p "${TESTRUNSDIR}/${testname}/ardana_logs"


        # Make sure we have no cruft from previous runs
        (
            cd ardana-configuration-processor
            rm -rf persistent_state
            rm -rf stage

            # If there is a persistent state alongside the model then
            # reurun with that as input - i.e test the upgrade case
            if [ ${STATE} ]; then
                echo
                echo "Copying Persisted state from: ${STATE}"
                echo
                cp -r ../../${STATE} .
            fi
        )

        # Look for a file alongside the cloudConfig.yml called
        #  cp_opts.{STATE_TYPE} to see if we have any special options for this test
        conf_dir=`dirname ${conf}`
        CP_OPTS=""

        if [ -f ${conf_dir}/cp_opts.${STATE_TYPE} ]; then
            CP_OPTS=`cat ${conf_dir}/cp_opts.${STATE_TYPE}`
        fi

        # Run the CP with no exiting state (i.e. as a new install) or with the persisted
        # state provided in the test case
        run_tox | tee ${TESTRUNSDIR}/${testname}/ardana_logs/cp.log
        test_result=${PIPESTATUS[0]}
        if [[ ${can_fail}  == true ]]; then
            # Strip out anything except the error strings
            sed -i -e "s/.*#/#/" -e "/^[0-9]/d" -e "s/ *$//" ${TESTRUNSDIR}/${testname}/ardana_logs/errors.log
            # Sort the two error files, and the order from the CP is non deterministic
            sort ${TESTRUNSDIR}/${testname}/ardana_logs/errors.log >  ${TESTRUNSDIR}/${testname}/ardana_logs/errors.log.sorted
            sort $(dirname $conf)/../ref/errors > ${TESTRUNSDIR}/${testname}/ardana_logs/ref_errors.sorted
            diff -q ${TESTRUNSDIR}/${testname}/ardana_logs/ref_errors.sorted ${TESTRUNSDIR}/${testname}/ardana_logs/errors.log.sorted
            if [[ $? == 0 ]]; then
                echo
                echo "   **********************************************"
                echo "   *                                            *"
                echo "   *  Test passed: Errors match expected values *"
                echo "   *                                            *"
                echo "   **********************************************"
                echo
                got_expected_errors=true
            else
                echo
                echo "   **********************************************"
                echo "   *                                            *"
                echo "   *  Test failed: Expected errors don't match  *"
                echo "   *    < expected                              *"
                echo "   *    > actual                                *"
                echo "   *                                            *"
                echo "   **********************************************"
                echo
                diff $(dirname $conf)/../ref/errors ${TESTRUNSDIR}/${testname}/ardana_logs/errors.log
                got_expected_errors=false
                result=${test_result}
                test_result=2
            fi
        else
            got_expected_errors=true
            if [[ $test_result != 0 ]]; then
                result=${test_result}
            fi
        fi
        add_summary $1 ${testname} ${test_result} ${can_fail} ${got_expected_errors} ${TESTRUNSDIR}/summary/${STATE_TYPE}

        # Don't need to do any other runs for the error cases
        if [[ ${can_fail} == true ]]; then
            continue
        fi

        # Rerun the CP against state it just generated to make sure
        # it is always re-runable
        CP_OPTS=""
        if [ -f ${conf_dir}/cp_opts.generated ]; then
            CP_OPTS=`cat ${conf_dir}/cp_opts.generated`
        fi

        run_tox | tee ${TESTRUNSDIR}/${testname}/ardana_logs/cp.log
        test_result=${PIPESTATUS[0]}
        if [[ $test_result != 0 && $can_fail == false ]]; then
            result=${test_result}
        fi
        got_expected_errors=true
        add_summary $1 ${testname} ${test_result} ${can_fail} ${got_expected_errors} ${TESTRUNSDIR}/summary/new_state

    done
}

result=0
CP_OPTS=""

# Create a directory for the test results
TESTRUNSDIR="${TOPDIR}/test-runs"
rm -rf "${TESTRUNSDIR}"
mkdir "${TESTRUNSDIR}"
#mkdir -p ${TESTRUNSDIR}/summary/no_state
#mkdir -p ${TESTRUNSDIR}/summary/existing_state
#mkdir -p ${TESTRUNSDIR}/summary/new_state

if [[ $# == 0 ]]; then
   dirs="ardana-input-model-ref ardana-configuration-processor/Tests"
else
   dirs="$*"
fi

# Look for any additional service definitons and copy them into
# the core set
for dir in `find . -name "ardana-extensions-*"`; do
    for service_dir in `find $dir -name "services" -type d`; do
        echo "Adding additional services from $service_dir"
        cp -r $service_dir/* ardana-input-model/2.0/services
    done
done


for dir in $dirs; do
    if [[ -d $dir ]]; then
        run_tests $dir
    else
        echo "skip $dir"
    fi
done

cd ${TESTRUNSDIR}/summary
echo
echo
echo "Summary of results"
echo "=================="


dir=no_state
if [[ -d $dir ]]; then
    echo
    echo "Test with no state"
    echo "------------------"
    print_summary $dir
fi

dir=existing_state
if [[ -d $dir ]]; then
    echo
    echo "Test with persisted state"
    echo "-------------------------"
    print_summary $dir
fi

dir=new_state
if [[ -d $dir ]]; then
    echo
    echo "Test with generated persisted state"
    echo "-----------------------------------"
    print_summary $dir
fi

echo
echo
if [[ ${result} == 0 ]]; then
    echo "***************** PASSED ****************"
else
    echo "***************** FAILED ****************"
fi

exit ${result}

