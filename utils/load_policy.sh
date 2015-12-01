#!/bin/sh
# Author: John Homer, Xinming Ou
# Copyright (C) 2011, Argus Cybersecurity Lab, Kansas State University

policy_def=$1

echo "Load policy file policy.P with forced true/false values and cost assignments"

xsb <<EOF

['environment'].

load_dyn('primitive_facts.P').

load_dyn('derived_facts.P').

load_dyn('policy.P').

write_policy('primitive.costs', 'derived.costs', 'forced_values.sat').

EOF

echo "Call sat.py"
sat.py 
