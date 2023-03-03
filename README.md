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

#### [basic.rego]
Looking at the comment in this file it does not seem to be a policy rule that
is expected to be run by an external consumer:
```
# (Not sure if we need this, but I'm using it to test the docs build.)
```

#### [required_tasks.rego]
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


#### [task_bundle.rego]
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


#### [attestation_task_bundle.rego]

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


#### [attestation_type.rego]
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


#### [authorization.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.authorization.
policy/release/authorization_test.rego:
data.policy.release.authorization.test_no_authorization: PASS (1.258138ms)
data.policy.release.authorization.test_commit_does_not_match: PASS (2.131115ms)
data.policy.release.authorization.test_repo_does_not_match: PASS (2.246286ms)
--------------------------------------------------------------------------------
PASS: 3/3
```
Looking at the rules in this file I don't see anything that stands out that we
have not already noted previously in this document.

#### [base_image_registries.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.base_image_registries
policy/release/base_image_registries_test.rego:
data.policy.release.base_image_registries.test_acceptable_base_images: PASS (1.848358ms)
data.policy.release.base_image_registries.test_empty_base_images: PASS (1.197682ms)
data.policy.release.base_image_registries.test_unacceptable_base_images: PASS (3.118485ms)
data.policy.release.base_image_registries.test_missing_result: PASS (2.318952ms)
data.policy.release.base_image_registries.test_missing_rule_data: PASS (1.005555ms)
--------------------------------------------------------------------------------
PASS: 5/5
```

Looking at the rules in this file I don't see anything that stands out that we
have not already noted previously in this document.

#### [buildah_build_task.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.buildah_build_task
policy/release/buildah_build_task_test.rego:
data.policy.release.buildah_build_task.test_good_dockerfile_param: PASS (1.497137ms)
data.policy.release.buildah_build_task.test_dockerfile_param_https_source: PASS (1.702602ms)
data.policy.release.buildah_build_task.test_dockerfile_param_http_source: PASS (1.642195ms)
data.policy.release.buildah_build_task.test_dockerfile_param_not_included: PASS (1.841453ms)
data.policy.release.buildah_build_task.test_task_not_named_buildah: PASS (994.518µs)
data.policy.release.buildah_build_task.test_missing_pipeline_run_attestations: PASS (353.43µs)
--------------------------------------------------------------------------------
PASS: 6/6
```
One of the rules in this file uses the OPA builtin function [startwith]:
```
_not_allowed_prefix(search) if {
	not_allowed := ["http://", "https://"]
	startswith(search, not_allowed[_])
}
```
In seedwing-policy there is a [string::regexp] which could probably be used
to accomplish the same thing.
Other than that I don't see anything that stands out that we have not already
noted previously in this document.


#### [hermetic_build_task.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.hermetic_build_task
policy/release/hermetic_build_task_test.rego:
data.policy.release.hermetic_build_task.test_hermetic_build: PASS (1.891496ms)
data.policy.release.hermetic_build_task.test_not_hermetic_build: PASS (3.44756ms)
--------------------------------------------------------------------------------
PASS: 2/2
```

Looking at the rules in this file I don't see anything that stands out that we
have not already noted previously in this document.

#### [java.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.java
policy/release/java_test.rego:
data.policy.release.java.test_all_good: PASS (1.788661ms)
data.policy.release.java.test_has_foreign: PASS (1.885362ms)
data.policy.release.java.test_unacceptable_bundle: PASS (1.269787ms)
data.policy.release.java.test_missing_rule_data: PASS (1.435648ms)
--------------------------------------------------------------------------------
PASS: 4/4
```

Looking at the rules in this file I don't see anything that stands out that we
have not already noted previously in this document.

#### [slsa_build_build_service.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.slsa_build_build_service
policy/release/slsa_build_build_service_test.rego:
data.policy.release.slsa_build_build_service.test_all_good: PASS (753.356µs)
data.policy.release.slsa_build_build_service.test_missing_builder_id: PASS (1.239524ms)
data.policy.release.slsa_build_build_service.test_unexpected_builder_id: PASS (1.195689ms)
--------------------------------------------------------------------------------
PASS: 3/3
```
There are only two rules in this file and I don't see anything that stands out
that we have not already noted previously in this document.

#### [slsa_build_scripted_build.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.slsa_build_scripted_build
policy/release/slsa_build_scripted_build_test.rego:
data.policy.release.slsa_build_scripted_build.test_all_good: PASS (4.925196ms)
data.policy.release.slsa_build_scripted_build.test_scattered_results: PASS (2.878153ms)
data.policy.release.slsa_build_scripted_build.test_missing_task_steps: PASS (3.817019ms)
data.policy.release.slsa_build_scripted_build.test_empty_task_steps: PASS (3.904915ms)
data.policy.release.slsa_build_scripted_build.test_results_missing_value_url: PASS (2.651686ms)
data.policy.release.slsa_build_scripted_build.test_results_missing_value_digest: PASS (4.451127ms)
data.policy.release.slsa_build_scripted_build.test_results_empty_value_url: PASS (3.240028ms)
data.policy.release.slsa_build_scripted_build.test_results_empty_value_digest: PASS (2.317614ms)
data.policy.release.slsa_build_scripted_build.test_subject_mismatch: PASS (3.999751ms)
data.policy.release.slsa_build_scripted_build.test_subject_with_tag_and_digest_is_good: PASS (3.175914ms)
data.policy.release.slsa_build_scripted_build.test_subject_with_tag_and_digest_mismatch_tag_is_good: PASS (4.564522ms)
data.policy.release.slsa_build_scripted_build.test_subject_with_tag_and_digest_mismatch_digest_fails: PASS (3.595482ms)
--------------------------------------------------------------------------------
PASS: 12/12
```

```
# METADATA
# title: Mismatch subject
# description: |-
#   The subject of the attestations must match the IMAGE_DIGEST and
#   IMAGE_URL values from the build task.
# custom:
#   short_name: subject_build_task_mismatch
#   failure_msg: The attestation subject, %q, does not match the build task image, %q
#   collections:
#   - slsa1
#   - slsa2
#   - slsa3
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	build_task := tkn.build_task(attestation)

	some subject in attestation.subject

	subject_image_ref := concat("@", [subject.name, subject_digest(subject)])
	result_image_ref := concat("@", [
		tkn.task_result(build_task, "IMAGE_URL"),
		tkn.task_result(build_task, "IMAGE_DIGEST"),
	])

	not image.equal_ref(subject_image_ref, result_image_ref)

	result := lib.result_helper(rego.metadata.chain(), [subject_image_ref, result_image_ref])
}
```
The OPA builtin function [concat] joins a set of arrays of strings allowing a
delimiter to be specified. Apart from that I don't see anything that stands out
that we have not already noted previously in this document.


#### [slsa_provenance_available.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.slsa_provenance_available
policy/release/slsa_provenance_available_test.rego:
data.policy.release.slsa_provenance_available.test_expected_predicate_type: PASS (660.988µs)
data.policy.release.slsa_provenance_available.test_unexpected_predicate_type: PASS (1.318552ms)
--------------------------------------------------------------------------------
PASS: 2/2
```
This file only contains a single rule. This rules also uses the builtin
[concat] function but apart from that I don't see anything that stands out
that we have not already noted previously in this document.


#### [slsa_source_version_controlled.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.slsa_source_version_controlled
policy/release/slsa_source_version_controlled_test.rego:
data.policy.release.slsa_source_version_controlled.test_all_good: PASS (834.294µs)
data.policy.release.slsa_source_version_controlled.test_non_git_uri: PASS (1.610291ms)
data.policy.release.slsa_source_version_controlled.test_non_git_commit: PASS (1.818546ms)
data.policy.release.slsa_source_version_controlled.test_invalid_materials: PASS (1.250646ms)
--------------------------------------------------------------------------------
PASS: 4/4
```

```
# METADATA
# title: Material with git commit digest
# description: |-
#   Each entry in the predicate.materials array of the attestation includes
#   a SHA1 digest which corresponds to a git commit.
# custom:
#   short_name: material_without_git_commit
#   failure_msg: Material digest %q is not a git commit
#   collections:
#   - minimal
#   - slsa2
#   - slsa3
#
deny contains result if {
	some material in materials
	commit := material.digest.sha1
	not regex.match("^[a-f0-9]{40}$", commit)
	result := lib.result_helper(rego.metadata.chain(), [commit])
}
```
Notice the usage of the [regex.match] builtin function. seedwing policy engine
has a builtin function [string::regexp] that could be used in this case. 
Apart from that I don't see anything that stands out that we have not already
noted previously in this document.

#### [step_image_registries.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.step_image_registries
policy/release/step_image_registries_test.rego:
data.policy.release.step_image_registries.test_image_registry_valid: PASS (952.948µs)
data.policy.release.step_image_registries.test_attestation_type_invalid: PASS (1.419498ms)
data.policy.release.step_image_registries.test_missing_rule_data: PASS (801.222µs)
--------------------------------------------------------------------------------
PASS: 3/3
```

I could not find anything that stands out that we have not already noted
previously in this document.

#### [tasks.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.tasks
policy/release/tasks_test.rego:
data.policy.release.tasks.test_required_tasks_met: PASS (10.880552ms)
data.policy.release.tasks.test_required_tasks_met_no_label: PASS (20.863289ms)
data.policy.release.tasks.test_required_tasks_warning_no_label: PASS (5.029754ms)
data.policy.release.tasks.test_required_tasks_not_met: PASS (10.506739ms)
data.policy.release.tasks.test_future_required_tasks_met: PASS (10.110137ms)
data.policy.release.tasks.test_future_required_tasks_not_met: PASS (9.739569ms)
data.policy.release.tasks.test_extra_tasks_ignored: PASS (20.555399ms)
data.policy.release.tasks.test_current_equal_latest: PASS (8.079064ms)
data.policy.release.tasks.test_current_equal_latest_also: PASS (11.771365ms)
data.policy.release.tasks.test_no_tasks_present: PASS (1.21569ms)
data.policy.release.tasks.test_parameterized: PASS (9.539765ms)
data.policy.release.tasks.test_missing_required_tasks_data: PASS (3.263714ms)
data.policy.release.tasks.test_missing_required_pipeline_data: PASS (4.462743ms)
--------------------------------------------------------------------------------
PASS: 13/13
```

I could not find anything that stands out that we have not already noted
previously in this document.

#### [test.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.policy.release.test
policy/release/test_test.rego:
data.policy.release.test.test_needs_non_empty_data: PASS (2.767841ms)
data.policy.release.test.test_needs_tests_with_results: PASS (1.967185ms)
data.policy.release.test.test_needs_tests_with_results_mixed: PASS (2.81911ms)
data.policy.release.test.test_success_data: PASS (1.63636ms)
data.policy.release.test.test_failure_data: PASS (2.40398ms)
data.policy.release.test.test_error_data: PASS (2.497653ms)
data.policy.release.test.test_mix_data: PASS (5.148552ms)
data.policy.release.test.test_skipped_is_not_deny: PASS (1.525487ms)
data.policy.release.test.test_skipped_is_warning: PASS (1.893744ms)
data.policy.release.test.test_warning_is_warning: PASS (1.973745ms)
data.policy.release.test.test_mixed_statuses: PASS (20.426434ms)
data.policy.release.test.test_unsupported_test_result: PASS (6.470674ms)
data.policy.release.test.test_missing_wrong_attestation_type: PASS (1.240121ms)
data.policy.release.test.test_wrong_attestation_type: PASS (1.221967ms)
--------------------------------------------------------------------------------
PASS: 14/14
```

I could not find anything that stands out that we have not already noted
previously in this document.

#### [lib/attestations.rego]
This file is located in `policy/release/lib` but its is in the package `lib`.
So running the tests for this will run all tests in the lib package:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.test

policy/release/lib/attestations_test.rego:
data.lib.test_pr_attestations: PASS (1.812474ms)
data.lib.test_tr_attestations: PASS (1.08494ms)
data.lib.test_att_mock_helper: PASS (548.6µs)
data.lib.test_att_mock_helper_ref: PASS (518.411µs)
data.lib.test_results_from_tests: PASS (1.933506ms)
data.lib.test_task_in_pipelinerun: PASS (1.15716ms)
data.lib.test_task_not_in_pipelinerun: PASS (410.277µs)
data.lib.test_result_in_task: PASS (509.591µs)
data.lib.test_result_not_in_task: PASS (466.433µs)
data.lib.test_task_succeeded: PASS (434.931µs)
data.lib.test_task_not_succeeded: PASS (453.579µs)
--------------------------------------------------------------------------------
PASS: 27/27
```

I could not find anything that stands out that we have not already noted
previously in this document.


### lib package


#### [array_helpers.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.arrays
policy/lib/array_helpers_test.rego:
data.lib.arrays.test_rank: PASS (5.769567ms)
data.lib.arrays.test_sort_by: PASS (12.339149ms)
data.lib.arrays.test_sort_by_mixed_types: PASS (2.620735ms)
data.lib.arrays.test_le: PASS (1.170197ms)
--------------------------------------------------------------------------------
PASS: 4/4
```

I could not find anything that stands out that we have not already noted
previously in this document.

#### [assertions.rego]
This is used for internal testing so I'm going to skip it.

#### [bundles.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.bundles
policy/lib/bundles_test.rego:
data.lib.bundles.test_disallowed_task_reference: PASS (833.448µs)
data.lib.bundles.test_empty_task_bundle_reference: PASS (603.535µs)
data.lib.bundles.test_unpinned_task_bundle: PASS (1.424388ms)
data.lib.bundles.test_acceptable_bundle: PASS (11.617093ms)
data.lib.bundles.test_out_of_date_task_bundle: PASS (7.360729ms)
data.lib.bundles.test_unacceptable_task_bundles: PASS (4.692559ms)
data.lib.bundles.test_is_equal: PASS (721.597µs)
data.lib.bundles.test_acceptable_bundle_is_acceptable: PASS (1.917327ms)
data.lib.bundles.test_unacceptable_bundle_is_unacceptable: PASS (840.708µs)
data.lib.bundles.test_missing_required_data: PASS (291.419µs)
--------------------------------------------------------------------------------
PASS: 10/10
```

I could not find anything that stands out that we have not already noted
previously in this document.

#### [image.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.image
policy/lib/image_test.rego:
data.lib.image.test_parse: PASS (7.415269ms)
data.lib.image.test_equal: PASS (12.218698ms)
--------------------------------------------------------------------------------
PASS: 2/2
```

```
# parse returns a data structure representing the different portions
# of the OCI image reference.
parse(ref) = d {
	digest_parts := split(ref, "@")
	digest := _get(digest_parts, 1, "")

	contains(digest_parts[0], "/")
	repo_parts := split(digest_parts[0], "/")

	tag_parts := split(repo_parts[count(repo_parts) - 1], ":")
	count(tag_parts) <= 2
	tag := _get(tag_parts, 1, "")

	repo := concat(
		"/",
		array.concat(
			array.slice(repo_parts, 0, count(repo_parts) - 1),
			[tag_parts[0]],
		),
	)

	d := {
		"digest": digest,
		"repo": repo,
		"tag": tag,
	}
}
```
Notice the usage of the OPA builtin functions [contains], [split],
[array.concat], and [array.slice].

```
# equal_ref returns true if two image references point to the same image,
# ignoring the tag. This complements the case where all parts of the reference
# need to be equal.
equal_ref(ref1, ref2) {
	img1 := parse(ref1)
	img2 := parse(ref2)

	# need to make sure that the digest of one reference is present, otherwise we
	# might end up comparing image references without tags and digests. equal_ref is
	# commutative, so we can check that the digest exists for one of the references,
	# in this case img1
	img1.digest != ""
	object.remove(img1, ["tag"]) == object.remove(img2, ["tag"])
}
```
Notice the usage of the OPA builtin function [object.remove].

Apart from the usages of the above OPA builtin functions I could not find
anything that stands out that we have not already noted previously in this
document.


#### [refs.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.refs
policy/lib/refs_test.rego:
data.lib.refs.test_bundle_in_pipelinerun: PASS (610.768µs)
data.lib.refs.test_bundle_resolver_in_pipelinerun: PASS (995.654µs)
data.lib.refs.test_bundle_in_pipeline: PASS (445.914µs)
data.lib.refs.test_bundle_resolver_in_pipeline: PASS (836.351µs)
data.lib.refs.test_bundle_in_pipelinerun_with_defaults: PASS (380.937µs)
data.lib.refs.test_bundle_resolver_in_pipelinerun_with_defaults: PASS (729.667µs)
--------------------------------------------------------------------------------
PASS: 6/6
```

I could not find anything that stands out that we have not already noted
previously in this document.

#### [result_helper.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.test_result_helper
policy/lib/result_helper_test.rego:
data.lib.test_result_helper: PASS (1.006521ms)
data.lib.test_result_helper_with_collections: PASS (1.049584ms)
data.lib.test_result_helper_with_term: PASS (1.712958ms)
--------------------------------------------------------------------------------
PASS: 3/3
```
result_helper_with_term(chain, failure_sprintf_params, term) := result {
	result := object.union(result_helper(chain, failure_sprintf_params), {"term": term})
}
```
Notice the usage of the OPA builtin function [object.union]. Apart from that I
could not find anything that stands out that we have not already noted
previously in this document.

#### [rule_data.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.test_rule_data
policy/lib/rule_data_test.rego:
data.lib.test_rule_data: PASS (587.105µs)
data.lib.test_rule_data_defaults: PASS (172.991µs)
--------------------------------------------------------------------------------
PASS: 2/2
```
Contains default values that can be overridden using data/rule-data.yaml.

#### [set_helpers.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.test_
...
policy/lib/set_helpers_test.rego:
data.lib.test_to_set: PASS (376.71µs)
data.lib.test_included_in: PASS (266.578µs)
data.lib.test_any_included_in: PASS (970.486µs)
data.lib.test_all_included_in: PASS (395.886µs)
data.lib.test_none_included_in: PASS (489.773µs)
data.lib.test_any_not_included_in: PASS (513.707µs)
```

I could not find anything that stands out that we have not already noted
previously in this document.

#### [string_utils.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.test_
...
policy/lib/string_utils_test.rego:
data.lib.test_quoted_values_string: PASS (433.481µs) 
```

I could not find anything that stands out that we have not already noted
previously in this document.

#### [time.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.time
policy/lib/time_test.rego:
data.lib.time.test_when_rule_precedence: PASS (484.78µs)
data.lib.time.test_when_package_precedence: PASS (262.631µs)
data.lib.time.test_effective_current_time_ns: PASS (1.001536ms)
data.lib.time.test_most_current: PASS (4.16015ms)
data.lib.time.test_future_items: PASS (959.12µs)
data.lib.time.test_acceptable_items: PASS (2.921775ms)
data.lib.time.test_newest: PASS (2.81541ms)
--------------------------------------------------------------------------------
PASS: 7/7
```
```
# Handle edge case where data.config is not present
# (We can't do `object.get(data, ...)` for some reason)
effective_current_time_ns = now_ns {
	not data.config
	now_ns := time.now_ns()
}
```
Notice the usage of the buildin OPA [time] functions in this file. Apart from
that I could not find anything that stands out that we have not already noted
previously in this document.

#### [tekton/task.rego]
The tests for these rules can be run using the following command:
```console
$ opa test ./data/rule_data.yml ./policy checks -v -r data.lib.tkn
policy/lib/tekton/task_test.rego:
data.lib.tkn.test_latest_required_tasks: PASS (5.382ms)
data.lib.tkn.test_current_required_tasks: PASS (2.674674ms)
data.lib.tkn.test_tasks_from_attestation: PASS (874.874µs)
data.lib.tkn.test_tasks_from_pipeline: PASS (1.189763ms)
data.lib.tkn.test_tasks_from_partial_pipeline: PASS (1.109018ms)
data.lib.tkn.test_tasks_not_found: PASS (246.716µs)
data.lib.tkn.test_task_param: PASS (392.174µs)
data.lib.tkn.test_task_result: PASS (382.713µs)
data.lib.tkn.test_tasks_from_attestation#01: PASS (5.379755ms)
data.lib.tkn.test_tasks_from_pipeline#01: PASS (7.468758ms)
data.lib.tkn.test_build_task: PASS (1.523955ms)
data.lib.tkn.test_build_task_not_found: PASS (1.974705ms)
data.lib.tkn.test_task_data_bundle_ref: PASS (379.39µs)
data.lib.tkn.test_task_data_no_bundle_Ref: PASS (290.485µs)
data.lib.tkn.test_missing_required_tasks_data: PASS (351.136µs)
--------------------------------------------------------------------------------
PASS: 15/15
```
```
# build_task returns the build task found in the attestation
build_task(attestation) := task if {
	some task in tasks(attestation)

	image_url := task_result(task, "IMAGE_URL")
	count(trim_space(image_url)) > 0

	image_digest := task_result(task, "IMAGE_DIGEST")
	count(trim_space(image_digest)) > 0
}
```
Notice the usage of the OPA builtin function [trim_space]. Apart from that I
could not find anything that stands out that we have not already noted
previously in this document.


### Enterprise Contract CLI
This section will try to explain and show an example of using the ec-policies
using [Enterprise Contract CLI]

#### Building
```console
$ make build
❱ dist/ec_linux_amd64
go: downloading muzzammil.xyz/jsonc v1.0.0
../../../../go/pkg/mod/github.com/open-policy-agent/conftest@v0.39.2/parser/jsonc/jsonc.go:6:2: unrecognized import path "muzzammil.xyz/jsonc": parse https://muzzammil.xyz/jsonc?go-get=1: no go-import meta tags (meta tag github.com/muhammadmuzzammil1998/jsonc did not match import path muzzammil.xyz/jsonc)
make: *** [Makefile:43: dist/ec_linux_amd64] Error 1
```
I spent around two hours trying to figure this out. It looks like the github
repo was renamed/moved and it currently redirected to
https://github.com/muhammadmuzzammil1998/jsonc. Just updating the dependency
in go.mod dit not allow the build command to succeed as there seems to be
transitive dependencies that also have the same dependencies and will fail
with a similar message. But cloning that repo locally and then using a replace
in go.mod seems to work:
```go
replace muzzammil.xyz/jsonc => /home/danielbevenius/work/security/hacbs/jsonc
```
Building with the above change:
```console
$ make build
❱ dist/ec_linux_amd64
❱ build
❱ build
❱ build
```
And we can check the build `ec` executable:
```console
$ ./dist/ec version
Version                     v0.1.1008-f003128
Source ID                   f00312855c29b1ede72ca0aadbfca3f4e02eb01f
Change date                 2023-03-02 20:23:33 +0000 UTC (12 hours ago)
ECC                         v0.0.0-20221220151524-ad0f637efacf
OPA                         v0.49.2
Conftest                    v0.39.2
Red Hat AppStudio (shared)  v0.0.0-20220615221006-a71c1aa4b97f
Cosign                      v1.13.1
Sigstore                    v1.5.2
Rekor                       v0.12.1-0.20220915152154-4bb6f441c1b2
Tekton Pipeline             v0.42.0
Kubernetes Client           v0.26.2
```

#### Running
```console
$ ./hack/simple-demo.sh --debug
+ IMAGE=quay.io/redhat-appstudio/ec-golden-image:latest
+ PUBLIC_KEY='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEODgxyIz09vBqJlXXzjp/X2h17WIt
jCVQhnDYVWHvXhw6rgqGeg6NTUxIEhRQqQZaF9mcBotHkuYGJfYZbai+FA==
-----END PUBLIC KEY-----'
+ POLICY_SOURCE=quay.io/hacbs-contract/ec-release-policy:latest
+ DATA_SOURCE=quay.io/hacbs-contract/ec-policy-data:latest
+ POLICY='{
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEODgxyIz09vBqJlXXzjp/X2h17WIt\njCVQhnDYVWHvXhw6rgqGeg6NTUxIEhRQqQZaF9mcBotHkuYGJfYZbai+FA==\n-----END PUBLIC KEY-----",
  "sources": [
    {
      "name": "EC Policies",
      "policy": [
        "quay.io/hacbs-contract/ec-release-policy:latest"
      ],
      "data": [
        "quay.io/hacbs-contract/ec-policy-data:latest"
      ]
    }
  ],
  "configuration": {
    "exclude": [
    ],
    "include": [
      "*"
    ]
  }
}'
+ OPTS=--debug
++ git rev-parse --show-toplevel
+ MAIN_GO=/home/danielbevenius/work/security/hacbs/ec-cli/main.go
+ go run /home/danielbevenius/work/security/hacbs/ec-cli/main.go validate image --image quay.io/redhat-appstudio/ec-golden-image:latest --policy '{
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEODgxyIz09vBqJlXXzjp/X2h17WIt\njCVQhnDYVWHvXhw6rgqGeg6NTUxIEhRQqQZaF9mcBotHkuYGJfYZbai+FA==\n-----END PUBLIC KEY-----",
  "sources": [
    {
      "name": "EC Policies",
      "policy": [
        "quay.io/hacbs-contract/ec-release-policy:latest"
      ],
      "data": [
        "quay.io/hacbs-contract/ec-policy-data:latest"
      ]
    }
  ],
  "configuration": {
    "exclude": [
    ],
    "include": [
      "*"
    ]
  }
}' --debug
+ yq -P
DEBU[0000] input.go:63 DetermineInputSpec Generating application snapshot from imageRef quay.io/redhat-appstudio/ec-golden-image:latest 
DEBU[0000] policy.go:129 NewPolicy Read EnterpriseContractPolicy as JSON        
DEBU[0000] policy.go:213 parseEffectiveTime Chosen to use effective time of `now`, using current time 2023-03-03T09:29:33Z 
DEBU[0000] validate.go:40 ValidateImage Validating image quay.io/redhat-appstudio/ec-golden-image:latest 
DEBU[0000] application_snapshot_image.go:175 SetImageURL Parsed image url quay.io/redhat-appstudio/ec-golden-image:latest 
DEBU[0000] application_snapshot_image.go:111 NewApplicationSnapshotImage Fetching policy source group 'EC Policies'   
DEBU[0000] application_snapshot_image.go:119 NewApplicationSnapshotImage policySource: &source.PolicyUrl{Url:"quay.io/hacbs-contract/ec-release-policy:latest", Kind:"policy"} 
DEBU[0000] application_snapshot_image.go:119 NewApplicationSnapshotImage policySource: &source.PolicyUrl{Url:"quay.io/hacbs-contract/ec-policy-data:latest", Kind:"data"} 
DEBU[0000] conftest_evaluator.go:109 NewConftestEvaluator Created work dir /tmp/ec-work-478101805      
DEBU[0000] conftest_evaluator.go:372 createConfigJSON Include rules found. These will be written to file /tmp/ec-work-478101805/data 
DEBU[0000] conftest_evaluator.go:376 createConfigJSON Exclude rules found. These will be written to file /tmp/ec-work-478101805/data 
DEBU[0000] conftest_evaluator.go:380 createConfigJSON Collections found. These will be written to file /tmp/ec-work-478101805/data 
DEBU[0000] policy.go:199 EffectiveTime Using effective time: 2023-03-03T09:29:33Z   
DEBU[0000] conftest_evaluator.go:415 createConfigJSON Writing config data to /tmp/ec-work-478101805/data/config.json: "{\n    \"config\": {\n        \"policy\": {\n            \"exclude\": [],\n            \"include\": [\n                \"*\"\n            ],\n            \"when_ns\": 1677835773015926041\n        }\n    }\n}" 
DEBU[0000] conftest_evaluator.go:115 NewConftestEvaluator Conftest test runner created                 
DEBU[0000] application_snapshot_image.go:128 NewApplicationSnapshotImage Conftest evaluator initialized               
DEBU[0001] application_snapshot_image.go:164 ValidateImageAccess Resp: &{MediaType:application/vnd.oci.image.manifest.v1+json Size:996 Digest:sha256:2a84336bbe74f06634f947506c93a597540ba157d75419817fb8edc3adeb4005 Data:[] URLs:[] Annotations:map[] Platform:<nil>} 
DEBU[0001] output.go:82 SetImageAccessibleCheckFromError Image access check passed                    
DEBU[0001] validate.go:136 resolveAndSetImageUrl Resolved image to quay.io/redhat-appstudio/ec-golden-image@sha256:2a84336bbe74f06634f947506c93a597540ba157d75419817fb8edc3adeb4005 
DEBU[0001] application_snapshot_image.go:175 SetImageURL Parsed image url quay.io/redhat-appstudio/ec-golden-image@sha256:2a84336bbe74f06634f947506c93a597540ba157d75419817fb8edc3adeb4005 
DEBU[0002] output.go:101 SetImageSignatureCheckFromError Image signature check failed                 
DEBU[0003] output.go:123 SetAttestationSignatureCheckFromError Image attestation signature check failed     
success: false
components:
  - name: Unnamed
    containerImage: quay.io/redhat-appstudio/ec-golden-image@sha256:2a84336bbe74f06634f947506c93a597540ba157d75419817fb8edc3adeb4005
    violations:
      - msg: No image signatures found matching the given public key. Verify the correct public key was provided, and a signature was created.
      - msg: No image attestations found matching the given public key. Verify the correct public key was provided, and one or more attestations were created.
    success: false
key: |
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEODgxyIz09vBqJlXXzjp/X2h17WIt
  jCVQhnDYVWHvXhw6rgqGeg6NTUxIEhRQqQZaF9mcBotHkuYGJfYZbai+FA==
  -----END PUBLIC KEY-----
```


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

### concat function
Should seedwing policy engine provide a builtin function similar to [concat]?

### comprehension
Is there way to do [comprehension] in seedwing?

### split function
Is there an equivalent to [split] in seedwing?

### contains function
Is there an equivalent to [contains] in seedwing?

### array.slice function
Is there an equivalent to [array.slice] in seedwing?

### array.concat function
Is there an equivalent to [array.concat] in seedwing?

### object.remove function
Is there an equivalent to [object.remove] in seedwing?

### object.union function
Is there an equivalent to [object.union] in seedwing?


[ec-policies]: https://github.com/hacbs-contract/ec-policies/
[policy]: https://github.com/hacbs-contract/ec-policies/tree/main/policy
[rego-builtin-functions]: https://www.openpolicyagent.org/docs/latest/policy-reference/#built-in-functions
[rego annotations]: https://www.openpolicyagent.org/docs/latest/annotations
[metadata]: #metadata-anchor
[count]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-aggregates-count
[startswith]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-strings-startswith
[string::regexp]: https://playground.seedwing.io/policy/string/regexp
[concat]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-strings-concat
[comprehensions]: https://www.openpolicyagent.org/docs/latest/policy-language/#comprehensions

[slsa_source_version_controlled.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/slsa_source_version_controlled.rego
[slsa_provenance_available.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/slsa_provenance_available.rego
[slsa_build_scripted_build.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/slsa_build_scripted_build.rego
[slsa_build_build_service.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/slsa_build_build_service.rego
[java.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/java.rego
[hermetic_build_task.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/hermetic_build_task.rego
[buildah_build_task.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/buildah_build_task.rego
[base_image_registries.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/base_image_registries.rego
[authorization.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/authorization.rego
[attestation_type.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/attestation_type.rego
[attestation_task_bundle.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/attestation_task_bundle.rego
[task_bundle.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/pipeline/task_bundle.rego
[required_tasks.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/pipeline/required_tasks.rego
[step_image_registries.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/pipeline/step_image_registries.rego
[basic.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/pipeline/basic.rego
[tasks.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/tasks.rego
[test.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/test.rego
[lib/attestations.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/release/lib/attestations.rego
[array_helpers.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/lib/array_helpers.rego
[bundles.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/lib/bundles.rego
[image.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/lib/image.rego
[refs.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/lib/refs.rego
[assertions.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/lib/assertions.rego
[result_helper.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/lib/result_helper.rego
[rule_data.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/lib/rule_data.rego
[set_helpers.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/lib/set_helpers.rego
[string_utils.rego]: https://github.com/hacbs-contract/ec-policies/blob/main/policy/lib/string_utils.rego
[regex.match]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-regex-regexmatch
[string::regexp]: https://playground.seedwing.io/policy/string/regexp
[split]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-strings-split
[array.concat]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-array-arrayconcat
[array.slice]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-array-arrayslice
[contains]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-strings-contains
[object.remove]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-object-objectremove
[object.union]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-object-objectunion
[time]: https://www.openpolicyagent.org/docs/latest/policy-reference/#builtin-strings-trim_space
[enterprise_contract_cli]: https://github.com/hacbs-contract/ec-cli
