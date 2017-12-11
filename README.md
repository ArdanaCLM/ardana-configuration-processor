## Ardana Input Model Reference

This repo contains the Ardana configuration processor.

This document contains a getting-started guide for the Ardana configuration processor (a-c-p).
It covers setup and how to run it against the ardana-input-model
and ardana-input-model-ref repos.

### Setup:
### NOTE: Steps 1 through 3 only need to be run once per clone of the a-c-p

1. Create a virtual environment

    virtualenv ~/venv_cp
    . ~/venv_cp/bin/activate

2. Clone the configuration processor (optional if you are already in a git checkout)

    git clone git://git.suse.provo.cloud/ardana/ardana-configuration-processor
    cd ardana-configuration-processor

3. Prepare the virtual environment:

    cd ConfigurationProcessor
    python setup.py sdist
    pip install dist/* ansible git-review coverage
    cd ..

4. Create a test ardana configuration processor environment:

   The important options supported by setup-ardana-cp.sh are
   outlined below; see usage message (setup-ardana-cp.sh -h)
   for a complete listing of available options.

    bash Scripts/setup-ardana-cp.sh ARD-001

   This will create the ARD-001 directory containing the input models.
   If the models exist at the same directory level as the a-c-p,
   they will be copied to ARD-001. Otherwise, they will be cloned
   into ARD-001.  A fresh clone can be triggered by using the -p option.
   The a-c-p will check each "example" model to create a baseline.
   This step can be skipped by using the -n option.

    bash Scripts/setup-ardana-cp.sh -n -p ARD-001

   If the a-c-p is run against the models, the script will print out the results.

   For Example:

   Passed: examples/entry-scale-esx-kvm-vsa
   Passed: examples/entry-scale-ironic-flat-network
   Passed: examples/entry-scale-ironic-multi-tenancy
   Passed: examples/entry-scale-kvm-ceph
   Passed: examples/entry-scale-kvm-esx-vsa-mml
   Passed: examples/entry-scale-kvm-vsa
   Passed: examples/entry-scale-kvm-vsa-mml
   Passed: examples/entry-scale-swift
   Passed: examples/mid-scale-kvm-vsa


5. To test a model change:

    Make changes to any of the models in ARD-001/ardana-input-model/

    bash Scripts/run_cp.sh -t ARD-001

    The important options supported by run_cp.sh are
    outlined below; see usage message (run_cp.sh -h)
    for a complete listing of available options.

-a   --run_all                      Run all models
-e   --enrcypt                      Encrypt ansible vars
-i   --ignore_persisted_state       Don't use persisted state
-I   --include:                     Add extra models r (ref) t (test) h (CI) a(all)
-k   --change_key                   Change encryption key
-N   --non_interactive              Run all models specified with -I option
-t   --quiet                        Only show CP result
-q   --target                       Target directroy to test, for example ARD-XXX
-v   --verbose_diff                 Show diferences in generated ansible
-z   --repeat                       Run with last selected model

Examples:

    Test all of the ardana-input-model-ref models

     bash Scripts/run_cp.sh -I r -N -t ARD-001

    Test against a specfic CI test by selecting from a list of models

     bash Scripts/run_cp.sh -I h -t ARD-001
