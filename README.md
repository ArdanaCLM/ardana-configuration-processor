## Ardana Input Model Reference

This repo contains the Aranda configuration processor.

This document contains a getting-started guide for the Ardana configuration processor.
It covers setup and how to run it against the ardana-input-model
and ardana-input-model-ref repos.

###Setup:

#### (These may get adjusted once this is published to GitHub.)

1) Create a virtual environment

    virtualenv ~/venv_cp
    . ~/venv_cp/bin/activate

2) Clone thoe configuration processor (optional if you are already in a git checkout)

    git clone git://git.suse.provo.cloud/ardana/ardana-configuration-processor
    cd ardana-configuration-processor

3) Prepare the virtual environment:

    cd ConfigurationProcessor
    python setup.py sdist
    pip install dist/* ansible git-review
    cd ..

4) Create a test configuration processor environment:

    bash Scripts/setup-ardana-cp.sh ARD-XXX

(This will clone the required repos and run the CP against each model to create a baseline)

5) To test a model change:

    Make changes to the models in ARD-XXX/ardana-input-model/2.0/examples

    cd ARD-XXX/ardana-configuration-processor/Driver
    ~/run_cp.sh

Options supported for run_cp.sh

-a   --run_all                      Run all models
-c   --commit                       Update persisted state
-C   --create_ref                   Save stage output as ref
-d   --remove_deleted_servers       Remove deleted servers from persisted state
-e   --enrcypt                      Encrypt ansible vars
-f   --free_unused_addresses        Remove unused addresses from persisted state
-h   --help                         Help
-i   --ignore_persisted_state       Don't use persisted state
-k   --change_key                   Change encryption key
-p   --refresh_all_secrets          Refresh all secrets
-P:  --credential_change_path       Credential Change Path
-q   --quiet                        Only show CP result
-t   --tests_only                   Only run kcp-tests
-r   --include_ref                  Include ref examples in list
-v   --verbose_diff                 Show diferences in generated ansible
-x   --leave_ext_name               Don't edit external name in network groups
-z   --repeat                       Run with last selected model
