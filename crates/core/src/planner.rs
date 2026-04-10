use std::collections::HashSet;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{PolicyAction, Report, RiskLevel};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScenarioPlan {
    pub generated_at: String,
    pub scan_id: String,
    pub assumptions: Vec<String>,
    pub scenarios: Vec<ScenarioProjection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScenarioProjection {
    pub scenario_id: String,
    pub title: String,
    pub strategy: ScenarioStrategy,
    pub recommendation_ids: Vec<String>,
    pub recommendation_count: u64,
    pub projected_space_saving_bytes: u64,
    pub risk_mix: ScenarioRiskMix,
    pub blocked_recommendation_count: u64,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStrategy {
    Conservative,
    Balanced,
    Aggressive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScenarioRiskMix {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
}

pub fn build_scenario_plan(report: &Report) -> ScenarioPlan {
    let blocked_recommendation_count = report
        .policy_decisions
        .iter()
        .filter(|decision| decision.action == PolicyAction::Blocked)
        .map(|decision| decision.recommendation_id.clone())
        .collect::<HashSet<_>>()
        .len() as u64;

    let scenarios = vec![
        build_projection(
            report,
            blocked_recommendation_count,
            "conservative",
            "Conservative",
            ScenarioStrategy::Conservative,
            |risk| matches!(risk, RiskLevel::Low),
        ),
        build_projection(
            report,
            blocked_recommendation_count,
            "balanced",
            "Balanced",
            ScenarioStrategy::Balanced,
            |risk| matches!(risk, RiskLevel::Low | RiskLevel::Medium),
        ),
        build_projection(
            report,
            blocked_recommendation_count,
            "aggressive",
            "Aggressive",
            ScenarioStrategy::Aggressive,
            |_| true,
        ),
    ];

    ScenarioPlan {
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        scan_id: report.scan_id.clone(),
        assumptions: vec![
            "Read-only what-if simulation: no file operations are performed.".to_string(),
            "Projected space saving sums estimated_impact.space_saving_bytes for included recommendations."
                .to_string(),
            "Recommendations without explicit byte estimates are treated as zero-byte impact."
                .to_string(),
        ],
        scenarios,
    }
}

fn build_projection<F>(
    report: &Report,
    blocked_recommendation_count: u64,
    scenario_id: &str,
    title: &str,
    strategy: ScenarioStrategy,
    include_risk: F,
) -> ScenarioProjection
where
    F: Fn(&RiskLevel) -> bool,
{
    let included = report
        .recommendations
        .iter()
        .filter(|recommendation| {
            recommendation.policy_safe && include_risk(&recommendation.risk_level)
        })
        .collect::<Vec<_>>();

    let recommendation_ids = included
        .iter()
        .map(|recommendation| recommendation.id.clone())
        .collect::<Vec<_>>();
    let projected_space_saving_bytes = included
        .iter()
        .filter_map(|recommendation| recommendation.estimated_impact.space_saving_bytes)
        .sum::<u64>();
    let risk_mix = included
        .iter()
        .fold(ScenarioRiskMix::default(), |mut mix, recommendation| {
            match recommendation.risk_level {
                RiskLevel::Low => mix.low += 1,
                RiskLevel::Medium => mix.medium += 1,
                RiskLevel::High => mix.high += 1,
            }
            mix
        });

    let mut notes = Vec::new();
    if recommendation_ids.is_empty() {
        notes.push("No policy-safe recommendations matched this scenario strategy.".to_string());
    }
    if blocked_recommendation_count > 0 {
        notes.push(format!(
            "{blocked_recommendation_count} recommendation(s) were blocked by policy and are excluded."
        ));
    }

    ScenarioProjection {
        scenario_id: scenario_id.to_string(),
        title: title.to_string(),
        strategy,
        recommendation_ids,
        recommendation_count: included.len() as u64,
        projected_space_saving_bytes,
        risk_mix,
        blocked_recommendation_count,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{
        EstimatedImpact, PolicyAction, PolicyDecision, Recommendation, Report, RiskLevel,
    };

    use super::{build_scenario_plan, ScenarioStrategy};

    #[test]
    fn builds_three_scenarios_with_expected_risk_filters() {
        let mut report: Report =
            serde_json::from_str(include_str!("../../../fixtures/sample-report.json"))
                .expect("fixture report parses");

        report.recommendations = vec![
            recommendation("low-safe", RiskLevel::Low, true, Some(100)),
            recommendation("medium-safe", RiskLevel::Medium, true, Some(200)),
            recommendation("high-safe", RiskLevel::High, true, None),
            recommendation("low-unsafe", RiskLevel::Low, false, Some(500)),
        ];
        report.policy_decisions = vec![PolicyDecision {
            policy_id: "safe_target_policy".to_string(),
            recommendation_id: "blocked-1".to_string(),
            action: PolicyAction::Blocked,
            rationale: "test".to_string(),
        }];

        let plan = build_scenario_plan(&report);
        assert_eq!(plan.scenarios.len(), 3);

        let conservative = plan
            .scenarios
            .iter()
            .find(|scenario| scenario.strategy == ScenarioStrategy::Conservative)
            .expect("conservative present");
        assert_eq!(
            conservative.recommendation_ids,
            vec!["low-safe".to_string()]
        );
        assert_eq!(conservative.projected_space_saving_bytes, 100);
        assert_eq!(conservative.risk_mix.low, 1);

        let balanced = plan
            .scenarios
            .iter()
            .find(|scenario| scenario.strategy == ScenarioStrategy::Balanced)
            .expect("balanced present");
        assert_eq!(
            balanced.recommendation_ids,
            vec!["low-safe".to_string(), "medium-safe".to_string()]
        );
        assert_eq!(balanced.projected_space_saving_bytes, 300);
        assert_eq!(balanced.risk_mix.low, 1);
        assert_eq!(balanced.risk_mix.medium, 1);

        let aggressive = plan
            .scenarios
            .iter()
            .find(|scenario| scenario.strategy == ScenarioStrategy::Aggressive)
            .expect("aggressive present");
        assert_eq!(
            aggressive.recommendation_ids,
            vec![
                "low-safe".to_string(),
                "medium-safe".to_string(),
                "high-safe".to_string()
            ]
        );
        assert_eq!(aggressive.projected_space_saving_bytes, 300);
        assert_eq!(aggressive.risk_mix.high, 1);
        assert_eq!(aggressive.blocked_recommendation_count, 1);
    }

    fn recommendation(
        id: &str,
        risk_level: RiskLevel,
        policy_safe: bool,
        space_saving_bytes: Option<u64>,
    ) -> Recommendation {
        Recommendation {
            id: id.to_string(),
            title: id.to_string(),
            rationale: "test".to_string(),
            confidence: 0.8,
            target_mount: None,
            policy_safe,
            policy_rules_applied: Vec::new(),
            policy_rules_blocked: Vec::new(),
            evidence: Vec::new(),
            next_steps: Vec::new(),
            estimated_impact: EstimatedImpact {
                space_saving_bytes,
                performance: None,
                risk_notes: None,
            },
            risk_level,
        }
    }
}
