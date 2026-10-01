use std::collections::BTreeMap;

use crate::{
    github::PullRequestDetails,
    queries::{Query, Statement},
    targets::PullRequest,
    value::Value,
};
use kunobi_jev::{Answer, ChoiceAnswer, Entry, NoulAnswer, ScoreAnswer};
use serde::Serialize;
use thiserror::Error;

pub(crate) mod jev;

#[derive(Debug, Error)]
pub enum AssessmentError {
    #[error("JEV error: {0}")]
    JevError(#[from] jev::JevError),
}

#[derive(Debug)]
pub enum Artifact {
    PullRequest(PullRequestAssessment),
    Diff(String),
}

pub trait Assessor {
    async fn assess<'a>(
        &self,
        artifact: &'a Artifact,
        query: &'a Query,
    ) -> Result<Assessment<'a>, AssessmentError>;
}

#[derive(Debug)]
pub enum PullRequestAssessment {
    Github(GithubPullRequestAssessment),
}

#[derive(Debug, Serialize)]
pub struct GithubPullRequestAssessment {
    owner: String,
    repo: String,
    pr_number: u32,
    title: Option<String>,
    description: Option<String>,
    changed_files: Vec<String>,
    diff: String,
}

impl From<(PullRequestDetails, PullRequest)> for GithubPullRequestAssessment {
    fn from(((pull, diff), request): (PullRequestDetails, PullRequest)) -> Self {
        Self {
            owner: request.owner,
            repo: request.repo,
            pr_number: request.pr_number,
            title: pull.title,
            description: pull.body,
            changed_files: diff
                .clone()
                .into_iter()
                .map(|entry| entry.filename)
                .collect(),
            diff: diff
                .into_iter()
                .map(|entry| entry.patch.unwrap_or_default())
                .collect::<Vec<String>>()
                .join("\n"),
        }
    }
}

impl TryFrom<&Artifact> for Entry {
    type Error = serde_json::Error;

    fn try_from(value: &Artifact) -> Result<Self, Self::Error> {
        match value {
            Artifact::PullRequest(PullRequestAssessment::Github(assessment)) => {
                let obj: serde_json::Map<String, serde_json::Value> =
                    serde_json::to_value(assessment)?
                        .as_object()
                        .cloned()
                        .unwrap_or_default();

                Ok(Entry::Object(obj))
            }
            Artifact::Diff(content) => Ok(content.into()),
        }
    }
}

#[derive(Debug)]
pub enum Verdict {
    Question(f64),
    Choice(String, f64, Vec<(String, f64)>),
    Score(f64, f64, BTreeMap<usize, (Value, f64)>),
    Unknown(Value),
}

impl From<&Answer> for Verdict {
    fn from(answer: &Answer) -> Self {
        match answer {
            Answer::Noul(NoulAnswer { noul: score }) => Verdict::Question(*score),
            Answer::Choice(ChoiceAnswer {
                choice: label,
                confidence: score,
                probabilities: choices,
            }) => {
                let choices = choices
                    .iter()
                    .map(|(label, score)| (label.clone(), *score))
                    .collect();
                Verdict::Choice(label.clone(), *score, choices)
            }
            Answer::Score(ScoreAnswer {
                score,
                confidence,
                legend,
                probabilities,
            }) => {
                let scores = probabilities
                    .iter()
                    .zip(legend.iter())
                    .map(|(score, label)| (*label.0 as usize, (label.1.clone().into(), *score.1)))
                    .collect();
                Verdict::Score(*score, *confidence, scores)
            }
            Answer::Unknown(v) => Verdict::Unknown(v.clone().into()),
        }
    }
}

#[derive(Debug)]
pub struct Assessment<'a> {
    verdicts: BTreeMap<String, (&'a Statement, Verdict)>,
    artifact: &'a Artifact,
}

impl<'a> Assessment<'a> {
    pub fn verdicts(&self) -> &BTreeMap<String, (&'a Statement, Verdict)> {
        &self.verdicts
    }

    pub fn artifact(&self) -> &'a Artifact {
        self.artifact
    }
}

impl<'a> From<Assessment<'a>> for Value {
    fn from(assessment: Assessment<'a>) -> Self {
        let verdicts = assessment
            .verdicts
            .into_iter()
            .map(|(key, (statement, verdict))| {
                let value = match verdict {
                    Verdict::Question(score) => Value::Number(score),
                    Verdict::Choice(label, score, choices) => {
                        let choices_value = Value::Object(
                            choices
                                .into_iter()
                                .map(|(label, score)| (label, Value::Number(score)))
                                .collect(),
                        );
                        let mut obj = BTreeMap::new();
                        obj.insert("label".to_string(), Value::Text(label));
                        obj.insert("score".to_string(), Value::Number(score));
                        obj.insert("choices".to_string(), choices_value);
                        Value::Object(obj)
                    }
                    Verdict::Score(score, confidence, scores) => {
                        let scores_value = Value::Object(
                            scores
                                .into_iter()
                                .map(|(index, (value, score))| {
                                    (
                                        index.to_string(),
                                        Value::Object(
                                            [
                                                ("value".to_string(), value),
                                                ("score".to_string(), Value::Number(score)),
                                            ]
                                            .into_iter()
                                            .collect(),
                                        ),
                                    )
                                })
                                .collect(),
                        );
                        let mut obj = BTreeMap::new();
                        obj.insert("score".to_string(), Value::Number(score));
                        obj.insert("confidence".to_string(), Value::Number(confidence));
                        obj.insert("scores".to_string(), scores_value);
                        Value::Object(obj)
                    }
                    Verdict::Unknown(value) => value,
                };
                (
                    key,
                    Value::Object(BTreeMap::from_iter([
                        ("statement".to_string(), statement.into()),
                        ("verdict".to_string(), value),
                    ])),
                )
            })
            .collect();
        Value::Object(verdicts)
    }
}
