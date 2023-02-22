# HACBS policies
This repository will take a look at the Hybrid Application Cloud Build Services
(HACBS) Enterprise Contract (EC) [ec-policies], and look at their usages of the
Rego rule language usage.

The goal is to make sure that the policy rules could be written in the Dogma
language, and if not open issues for functionality that may be missing. The
intention is `not` to re-write/translate all the ec-policies rules.

## HACBS Policy Rules
The HACBS policy rules can be found in [policy] which contains the following
directories:
* pipeline
* release
* lib

### pipeline package

#### [basic.rego](https://github.com/hacbs-contract/ec-policies/blob/main/policy/pipeline/basic.rego)
Looking at the comment in this file it does not seem to be a policy rule that
is expected to be run by an external consumer:
```
# (Not sure if we need this, but I'm using it to test the docs build.)
```

#### [required_tasks.rego](https://github.com/hacbs-contract/ec-policies/blob/main/policy/pipeline/required_tasks.rego)
This rule file contains polices related to Tekton pipelines.

The first policy rule is tested by `tasks.test_required_tasks_met`
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.pipeline.required_tasks.test_required_tasks
policy/pipeline/required_tasks_test.rego:
data.policy.pipeline.required_tasks.test_required_tasks_met: PASS (10.451165ms)
data.policy.pipeline.required_tasks.test_required_tasks_not_met: PASS (7.362276ms)
--------------------------------------------------------------------------------
PASS: 2/2
```
So those two test should verify that the input json document contains at least
on task element in `tasks` array.

As a reference the following is an example of the input JSON that these tests
handle:
<details><summary>pipline json</summary>

```json
{
  "kind": "Pipeline",
  "metadata": {
    "labels": {
      "pipelines.openshift.io/runtime": "fbc"
    },
    "name": "fbc"
  },
  "spec": {
    "finally": [],
    "tasks": [
      {
        "taskRef": {
          "bundle": "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
          "kind": "Task",
          "name": "buildah"
        }
      },
      {
        "taskRef": {
          "bundle": "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
          "kind": "Task",
          "name": "git-clone"
        }
      },
      {
        "params": [
          {
            "name": "POLICY_NAMESPACE",
            "value": "optional_checks"
          }
        ],
        "taskRef": {
          "bundle": "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
          "kind": "Task",
          "name": "sanity-label-check"
        }
      },
      {
        "params": [
          {
            "name": "POLICY_NAMESPACE",
            "value": "required_checks"
          }
        ],
        "taskRef": {
          "bundle": "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
          "kind": "Task",
          "name": "sanity-label-check"
        }
      }
    ]
  }
}
{
  "kind": "Pipeline",
  "metadata": {
    "labels": {
      "pipelines.openshift.io/runtime": "fbc"
    },
    "name": "fbc"
  },
  "spec": {
    "finally": [
      {
        "taskRef": {
          "bundle": "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
          "kind": "Task",
          "name": "buildah"
        }
      },
      {
        "taskRef": {
          "bundle": "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
          "kind": "Task",
          "name": "git-clone"
        }
      },
      {
        "params": [
          {
            "name": "POLICY_NAMESPACE",
            "value": "optional_checks"
          }
        ],
        "taskRef": {
          "bundle": "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
          "kind": "Task",
          "name": "sanity-label-check"
        }
      },
      {
        "params": [
          {
            "name": "POLICY_NAMESPACE",
            "value": "required_checks"
          }
        ],
        "taskRef": {
          "bundle": "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
          "kind": "Task",
          "name": "sanity-label-check"
        }
      }
    ],
    "tasks": []
  }
}
```

</details>

So this should verify that the input json document contains at least on task
element in `tasks` array.

[required_tasks.rs](./tests/pipeline/required_tasks.rs) contains a similar test
written in Rust and tests the
[required_tasks.dog](policy/pipeline/required_tasks.dog) Dogma policy rules
file:
```console
$ cargo t -- --show-output at_least_one_task
   Compiling hacbs-dogma-policies v0.1.0 (/home/danielbevenius/work/security/seedwing/hacbs-dogma-policies)
    Finished test [unoptimized + debuginfo] target(s) in 7.42s
     Running tests/tests.rs (target/debug/deps/tests-16c82c8c48b6735c)

running 2 tests
test pipeline::required_tasks::at_least_one_task ... ok
test pipeline::required_tasks::at_least_one_task_no_tasks ... ok

successes:

successes:
    pipeline::required_tasks::at_least_one_task
    pipeline::required_tasks::at_least_one_task_no_tasks

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.19s
```

One thing to note is how the rules are written in Rego, take for example the
following rule:
```
# METADATA
# title: Missing required task
# description: |-
#   This policy enforces that the required set of tasks are included
#   in the Pipeline definition.
# custom:
#   short_name: missing_required_task
#   failure_msg: Required task %q is missing
deny contains result if {
	count(tkn.tasks(input)) > 0

	# Get missing tasks by comparing with the default required task list
	some required_task in _missing_tasks(current_required_tasks)

	# Don't report an error if a task is required now, but not in the future
	required_task in latest_required_tasks
	result := lib.result_helper_with_term(rego.metadata.chain(), [required_task], required_task)
}
```
This rule was tested above using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.pipeline.required_tasks.test_required_tasks
```
If we take a look at the test for this it looks like this:
```
test_required_tasks_not_met if {
	missing_tasks := {"buildah"}
	pipeline := _pipeline_with_tasks_and_label(_expected_required_tasks - missing_tasks, [], [])

	expected := _missing_tasks_violation(missing_tasks)
	lib.assert_equal(expected, deny) with data["pipeline-required-tasks"] as _time_based_pipeline_required_tasks
		with input as pipeline
}
```
By just looking at the rule above I was not able to tell which rule this tests
was executing. I actually had to put a print statement into the rule to verify
which one rule it was running. But if I had looked closer the rule is `deny` so
all the rules with the name `deny` will be evaulated. This might just be my
own lack of knowledge of Rego but it would have been nice to named the rules
after what they are checking for, and then have a composite rule that checked
all (not sure if that is possible though). And this can also make test brittle
as changing on of `deny` rules in the .rego can cause failures in other tests
cases. This is something to keep in mind when reading Rego.


<a id="metadata-anchor"></a>
Also notice the comment that start with `METADATA` which are actually
[rego annotations] and are in yaml format. In the test above what is returned
is the following:
```console
{
  "code": "required_tasks.missing_required_task",
  "effective_on": "2022-01-01T00:00:00Z",
  "msg": "Required task \"buildah\" is missing", "term": "buildah"
}
```
The metadata can then be accessed in rules using builtin-functions like
`rego.metadata.chain()`. For example, printing out the output from that function
for our above test would display:
```console
[{
  "annotations": {
    "custom": {
      "failure_msg": "Required task %q is missing",
      "short_name": "missing_required_task"
    },
    "description": "This policy enforces that the required set of tasks are included\nin the Pipeline definition.",
    "scope": "rule",
    "title": "Missing required task"
  },
  "path": ["policy", "pipeline", "required_tasks", "deny"]
},{
  "annotations": {
    "description": "HACBS expects that certain Tekton tasks are executed during image builds.\nThis package includes policy rules to confirm that the pipeline definition\nincludes the required Tekton tasks.",
    "scope": "package"
  },
  "path": ["policy", "pipeline", "required_tasks"]}
```
This is passed to the function `lib.result_helper_with_term` in the above rule:
```
	result := lib.result_helper_with_term(rego.metadata.chain(), [required_task], required_task)
```
And that will delegate to `result_helper`:
```
result_helper_with_term(chain, failure_sprintf_params, term) := result {
	result := object.union(result_helper(chain, failure_sprintf_params), {"term": term})
}

result_helper(chain, failure_sprintf_params) := result {
	with_collections := {"collections": _rule_annotations(chain).custom.collections}
	result := object.union(_basic_result(chain, failure_sprintf_params), with_collections)
} else := result {
	result := _basic_result(chain, failure_sprintf_params)
}
```
Notice that `result_helper` contains an `else` statement and will stop when
the input does not match the `with_collections` rule, and then proceed to
execute the else block.



The metadata can also be displayed using the opa inspect command:
```console
$ opa inspect -a policy/pipeline
```


Looking at the rest of the rules in required_tasks.rego I can't see anything
that sticks out what would not be possible to write in Dogma.


#### [task_bundle.rego](https://github.com/hacbs-contract/ec-policies/blob/main/policy/pipeline/task_bundle.rego)
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.pipeline.task_bundle
policy/pipeline/task_bundle_test.rego:
data.policy.pipeline.task_bundle.test_bundle_not_exists: PASS (2.046607ms)
data.policy.pipeline.task_bundle.test_bundle_not_exists_empty_string: PASS (1.851684ms)
data.policy.pipeline.task_bundle.test_bundle_unpinned: PASS (1.744623ms)
data.policy.pipeline.task_bundle.test_bundle_reference_valid: PASS (2.993972ms)
data.policy.pipeline.task_bundle.test_acceptable_bundle_up_to_date: PASS (10.115315ms)
data.policy.pipeline.task_bundle.test_acceptable_bundle_out_of_date_past: PASS (10.998381ms)
data.policy.pipeline.task_bundle.test_acceptable_bundle_expired: PASS (9.678123ms)
data.policy.pipeline.task_bundle.test_missing_required_data: PASS (1.79935ms)
--------------------------------------------------------------------------------
PASS: 8/8
```
These rules operate/process/use the `tasks` array of the Tekton pipeline json:
```json
{
  "kind": "Pipeline",
  "metadata": {
    "labels": {
      "pipelines.openshift.io/runtime": "fbc"
    },
    "name": "fbc"
  },
  "spec": {
    "finally": [],
    "tasks": [
      {
        "taskRef": {
          "bundle": "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
          "kind": "Task",
          "name": "buildah"
        }
      }],
      ...
```
Lets take a closer look at one of these tests and start with the first one.
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.pipeline.task_bundle.test_bundle_not_exists$
policy/pipeline/task_bundle_test.rego:
data.policy.pipeline.task_bundle.test_bundle_not_exists: PASS (2.046295ms)
--------------------------------------------------------------------------------
PASS: 1/1
```
The `$` at then is so that the regular expression (`-r`) does not match other
test but this one.
The rule in this case looks like this:
```
# METADATA
# title: Task bundle was not used or is not defined
# description: |-
#   Check for existence of a task bundle. Enforcing this rule will
#   fail the contract if the task is not called from a bundle.
# custom:
#   short_name: disallowed_task_reference
#   failure_msg: Pipeline task '%s' does not contain a bundle reference
#
deny contains result if {
	some task in bundles.disallowed_task_reference(input.spec.tasks)
	result := lib.result_helper(rego.metadata.chain(), [task.name])
}
```
The `some` Rego keyword introduces a local variable. And notice that
`bundles.disallowed_task_reference` is a rule imported from using:
```
import data.lib.bundles
```
This package can be found in `ec-policies/policy/lib/bundles.rego`:
```
# Returns a subset of tasks that do not use a bundle reference.
disallowed_task_reference(tasks) = matches {
	matches := {task |
		task := tasks[_]
		not bundle(task)
	}
}
```
This is called comprehension and are like rules that have a head and a body.
The body will check for the absence of a bundle in the task and if that is the
case that task will be added to the array to be returned.

If we print the result from this test we will get:
```json
{
  "code": "task_bundle.disallowed_task_reference",
  "effective_on": "2022-01-01T00:00:00Z",
  "msg": "Pipeline task 'my-task' does not contain a bundle reference"
}
```

There does not look like there are any complicated rules in this file that
could not be written in Dogma.

Those are all the rules in `policy/pipeline/`.

### runtime package


#### [attestation_task_bundle.rego](https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/attestation_task_bundle.rego)

These test can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.attestation_task_bundle
policy/release/attestation_task_bundle_test.rego:
data.policy.release.attestation_task_bundle.test_bundle_not_exists: PASS (4.357773ms)
data.policy.release.attestation_task_bundle.test_bundle_not_exists_empty_string: PASS (2.534404ms)
data.policy.release.attestation_task_bundle.test_bundle_unpinned: PASS (2.209814ms)
data.policy.release.attestation_task_bundle.test_bundle_reference_valid: PASS (3.073418ms)
data.policy.release.attestation_task_bundle.test_acceptable_bundle_up_to_date: PASS (10.179267ms)
data.policy.release.attestation_task_bundle.test_acceptable_bundle_out_of_date_past: PASS (11.883647ms)
data.policy.release.attestation_task_bundle.test_acceptable_bundle_expired: PASS (10.735255ms)
data.policy.release.attestation_task_bundle.test_missing_required_data: PASS (926.592µs)
--------------------------------------------------------------------------------
PASS: 8/8
```

```
# METADATA                                                                         
# title: Task bundle was not used or is not defined                                
# description: |-                                                                  
#   Check for existence of a task bundle. Enforcing this rule will                 
#   fail the contract if the task is not called from a bundle.                     
# custom:                                                                          
#   short_name: disallowed_task_reference                                          
#   failure_msg: Pipeline task '%s' does not contain a bundle reference            
#   collections:                                                                   
#   - minimal                                                                      
#                                                                                  
deny[result] {                                                                     
      name := bundles.disallowed_task_reference(lib.tasks_from_pipelinerun)[_].name
      result := lib.result_helper(rego.metadata.chain(), [name])                 
} 
```
Again we see the usage of `bundles.disallowed_task_reference` which we now
know is in policy/lib/bundles.rego.

Also Notice the usage of `[_]` which will be turned into a `for` loop I think,
```
  result = []                                                             
  for name in bundles.disallowed_task_reference(lib.tasks_from_pipelinerun):
    result.append(lib.result_helper(rego.metadata.chain(), [name]))
```
And also notice that this returns `[result]`, which is an array/list so there
can be more than one.

The rests of the rules in this file follow the same pattern as well.


#### [attestation_type.rego](https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/attestation_type.rego)
The test can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.attestation_type.test_
policy/release/attestation_type_test.rego:
data.policy.release.attestation_type.test_allow_when_permitted: PASS (688.238µs)
data.policy.release.attestation_type.test_deny_when_not_permitted: PASS (1.410065ms)
data.policy.release.attestation_type.test_deny_when_missing_pipelinerun_attestations: PASS (880.901µs)
--------------------------------------------------------------------------------
PASS: 3/3

This .rego file only contains two rules.

```
# METADATA
# title: Unknown attestation type found
# description: |-
#   A sanity check to confirm the attestation found for the image has a known
#   attestation type.
# custom:
#   short_name: unknown_att_type
#   failure_msg: Unknown attestation type '%s'
#   collections:
#   - minimal
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	att_type := att._type
	not att_type in lib.rule_data("known_attestation_types")
	result := lib.result_helper(rego.metadata.chain(), [att_type])
}

# METADATA
# title: Missing pipelinerun attestation
# description: >
#   At least one PipelineRun attestation must be present.
# custom:
#   short_name: missing_pipelinerun_attestation
#   failure_msg: Missing pipelinerun attestation
#   collections:
#   - minimal
#
deny contains result if {
	count(lib.pipelinerun_attestations) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}
```
`count` is used in a number of rules. In this case I think that the
seedwing-policy builtin function `list::none<type> could be used. There
are other builtin functions for [list](https://playground.seedwing.io/policy/list/):
* all
* any
* head
* none
* some
* tail



__wip__


## Missing features
This section list features that exist in HACBS Policy Rules/Rego but are
currently not available in seedwing-policy-engine/Dogma (as far as I'm aware)

### HACBS rules custom results
The rules in HACBS return a result which contains information about the
success/failure. For example:
```console
{
  "code": "required_tasks.missing_required_task",
  "effective_on": "2022-01-01T00:00:00Z",
  "msg": "Required task \"buildah\" is missing",
  "term": "buildah"
}
```
I'm not sure this is possible at the moment with seedwing-policy-engine and
Dogma. The error messages are specified as metadata on the rules:
```
# METADATA
# title: Missing required task
# description: |-
#   This policy enforces that the required set of tasks are included
#   in the Pipeline definition.
# custom:
#   short_name: missing_required_task
#   failure_msg: Required task %q is missing
deny contains result if {
```
This [metadata] was discussed earlier in this document.


### list::count
Rego has a builtin function named [count] which returns the number of elements
in a collection or a string.

Should seedwing-policy engine have a builtin function similar to this. For
example:
```
list::count<anything>
```

[ec-policies]: https://github.com/hacbs-contract/ec-policies/
[policy]: https://github.com/hacbs-contract/ec-policies/tree/main/policy
[rego-builtin-functions]: https://www.openpolicyagent.org/docs/latest/policy-reference/#built-in-functions
[rego annotations]: https://www.openpolicyagent.org/docs/latest/annotations
[metadata]: #metadata-anchor
[count]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-aggregates-count
