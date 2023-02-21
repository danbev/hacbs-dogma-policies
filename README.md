# HACBS policies
This repository will take a look at the Hybrid Application Cloud Build Services
(HACBS) [policies], and look at their usages of the Rego rule language usage.

The goal is to make sure that the policy rules could be written in the Dogma
language, and if not open issues for functionality that may be missing. The
intention is not to re-write/translate all the HACBS Rego rules.

## HACBS Policy Rules
The HACBS policy rules can be found in [policy] which contains the following
directories:
* pipeline
* release
* lib

### pipeline

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


[policies]: https://github.com/hacbs-contract/ec-policies/
[policy]: https://github.com/hacbs-contract/ec-policies/tree/main/policy
[rego-builtin-functions]: https://www.openpolicyagent.org/docs/latest/policy-reference/#built-in-functions
