use seedwing_policy_engine::lang::builder::Builder;
use seedwing_policy_engine::lang::lir::EvalContext;
use seedwing_policy_engine::runtime::sources::Directory;
use seedwing_policy_engine::runtime::World;
use std::path::Path;

fn sources() -> Directory {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let policy = Path::new(&manifest_dir).join("policy").join("pipeline");
    Directory::new(policy)
}

async fn runtime() -> World {
    let sources = sources();
    let mut builder = Builder::new();
    let _result = builder.build(sources.iter());
    builder.finish().await.unwrap()
}

#[tokio::test]
async fn at_least_one_task_no_tasks() {
    let runtime = runtime().await;
    let input = r#"
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
    "tasks": []
  }
}
    "#;

    let result = runtime
        .evaluate(
            "required_tasks::at-least-one-task",
            input,
            EvalContext::default(),
        )
        .await;

    //println!("{:?}", result);
    assert!(!result.unwrap().satisfied());
}

#[tokio::test]
async fn at_least_one_task() {
    let runtime = runtime().await;
    let input = r#"
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
          "bundle": "registry.img/spam@sha256:4e388ab3",
          "kind": "Task",
          "name": "buildah"
        }
      }
    ]
  }
}
    "#;

    let result = runtime
        .evaluate(
            "required_tasks::at-least-one-task",
            input,
            EvalContext::default(),
        )
        .await;

    //println!("{:?}", result);
    assert!(!result.unwrap().satisfied());
}
