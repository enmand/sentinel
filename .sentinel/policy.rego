#  -*- mode: rego; -*-
# vim: set syntax=rego filetype=rego :

package sentinel

import rego.v1

#default disposition := data.dispositions.proceed

#disposition := data.dispositions.human-review if {
#    input.assessment.security_boundary >= 0.80
#}

#disposition := data.dispositions.canary if {
#    input.assessment.restore_complexity.score >= 1.5
#    not input.assessment.security_boundary >= 0.80
#}

#flags contains data.flags.security-review if {
#    input.assessment.security_boundary >= 0.70
#}

#flags contains data.flags.data-review if {
#    input.assessment.persistent_state >= 0.75
#}

flags contains data.flags["api-review"] if {
	input.assessment.external_contract >= 0
}

flags contains data.flags["rollback-plan-required"]

d contains data.sentinel.dispositions["human-review"]

results := {
	"disposition": d,
	"flags": flags,
}
