/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::{sync::Arc, time::Duration};

use ahash::AHashMap;
use directory::{backend::internal::manage::ManageDirectory, Type};
use store::{Store, Stores};
use trc::{EventType, MetricType, TOTAL_EVENT_COUNT};
use utils::config::{
    cron::SimpleCron,
    utils::{AsKey, ParseValue},
    Config, ConfigKey,
};

use crate::{
    expr::{tokenizer::TokenMap, Expression},
    manager::config::ConfigManager,
};

use super::{
    license::LicenseKey, llm::AiApiConfig, AlertContent, AlertContentToken, AlertMethod,
    Enterprise, MetricAlert, MetricStore, SpamFilterLlmConfig, TraceStore, Undelete,
};

impl Enterprise {
    pub async fn parse(
        config: &mut Config,
        config_manager: &ConfigManager,
        stores: &Stores,
        data: &Store,
    ) -> Option<Self> {
        // 始终返回一个有效的 Enterprise 实例
        Some(Enterprise {
            license: LicenseKey {
                valid_from: 0,
                valid_to: u64::MAX,
                domain: "unlocked".to_string(),
                accounts: u32::MAX,
            },
            undelete: config
                .property_or_default::<Option<Duration>>("storage.undelete.retention", "false")
                .unwrap_or_default()
                .map(|retention| Undelete { retention }),
            logo_url: config.value("enterprise.logo-url").map(|s| s.to_string()),
            trace_store: None,
            metrics_store: None,
            metrics_alerts: Vec::new(),
            spam_filter_llm: None,
            ai_apis: AHashMap::new(),
        })
    }
}

impl SpamFilterLlmConfig {
    pub fn parse(config: &mut Config, models: &AHashMap<String, Arc<AiApiConfig>>) -> Option<Self> {
        if !config
            .property_or_default::<bool>("spam-filter.llm.enable", "false")
            .unwrap_or_default()
        {
            return None;
        }
        let model = config.value_require_non_empty("spam-filter.llm.model")?;
        let model = if let Some(model) = models.get(model) {
            model.clone()
        } else {
            let message = format!("Model {model:?} not found in AI API configuration");
            config.new_build_error("spam-filter.llm.model", message);
            return None;
        };

        let llm = SpamFilterLlmConfig {
            model,
            temperature: config
                .property_or_default("spam-filter.llm.temperature", "0.5")
                .unwrap_or(0.5),
            prompt: config
                .value_require_non_empty("spam-filter.llm.prompt")?
                .to_string(),
            separator: config
                .value_require_non_empty("spam-filter.llm.separator")
                .unwrap_or_default()
                .chars()
                .next()
                .unwrap_or(','),
            index_category: config
                .property("spam-filter.llm.index.category")
                .unwrap_or_default(),
            index_confidence: config.property("spam-filter.llm.index.confidence"),
            index_explanation: config.property("spam-filter.llm.index.explanation"),
            categories: config
                .values("spam-filter.llm.categories")
                .map(|(_, v)| v.trim().to_uppercase())
                .collect(),
            confidence: config
                .values("spam-filter.llm.confidence")
                .map(|(_, v)| v.trim().to_uppercase())
                .collect(),
        };

        if llm.categories.is_empty() {
            config.new_build_error("spam-filter.llm.categories", "No categories defined");
            return None;
        }
        if llm.index_confidence.is_some() && llm.confidence.is_empty() {
            config.new_build_error(
                "spam-filter.llm.confidence",
                "Confidence index is defined but no confidence values are provided",
            );
            return None;
        }

        llm.into()
    }
}

pub fn parse_metric_alerts(config: &mut Config) -> Vec<MetricAlert> {
    let mut alerts = Vec::new();

    for metric_id in config
        .sub_keys("metrics.alerts", ".enable")
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
    {
        if let Some(alert) = parse_metric_alert(config, metric_id) {
            alerts.push(alert);
        }
    }

    alerts
}

fn parse_metric_alert(config: &mut Config, id: String) -> Option<MetricAlert> {
    if !config.property_or_default::<bool>(("metrics.alerts", id.as_str(), "enable"), "false")? {
        return None;
    }

    let mut alert = MetricAlert {
        condition: Expression::try_parse(
            config,
            ("metrics.alerts", id.as_str(), "condition"),
            &TokenMap::default().with_variables_map(
                EventType::variants()
                    .into_iter()
                    .map(|e| (sanitize_metric_name(e.name()), e.id() as u32))
                    .chain(MetricType::variants().iter().map(|m| {
                        (
                            sanitize_metric_name(m.name()),
                            m.code() as u32 + TOTAL_EVENT_COUNT as u32,
                        )
                    })),
            ),
        )?,
        method: Vec::new(),
        id,
    };
    let id_str = alert.id.as_str();

    if config
        .property_or_default::<bool>(("metrics.alerts", id_str, "notify.event.enable"), "false")
        .unwrap_or_default()
    {
        alert.method.push(AlertMethod::Event {
            message: parse_alert_content(
                ("metrics.alerts", id_str, "notify.event.message"),
                config,
            ),
        });
    }

    if config
        .property_or_default::<bool>(("metrics.alerts", id_str, "notify.email.enable"), "false")
        .unwrap_or_default()
    {
        let from_addr = config
            .value_require(("metrics.alerts", id_str, "notify.email.from-addr"))?
            .trim()
            .to_string();
        let from_name = config
            .value(("metrics.alerts", id_str, "notify.email.from-name"))
            .map(|s| s.to_string());
        let to = config
            .values(("metrics.alerts", id_str, "notify.email.to"))
            .filter_map(|(_, s)| {
                if s.contains('@') {
                    s.trim().to_string().into()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let subject =
            parse_alert_content(("metrics.alerts", id_str, "notify.email.subject"), config)?;
        let body = parse_alert_content(("metrics.alerts", id_str, "notify.email.body"), config)?;

        if !from_addr.contains('@') {
            config.new_build_error(
                ("metrics.alerts", id_str, "notify.email.from-addr"),
                "Invalid from email address",
            );
        }
        if to.is_empty() {
            config.new_build_error(
                ("metrics.alerts", id_str, "notify.email.to"),
                "Missing recipient address(es)",
            );
        }
        if subject.0.is_empty() {
            config.new_build_error(
                ("metrics.alerts", id_str, "notify.email.subject"),
                "Missing email subject",
            );
        }
        if body.0.is_empty() {
            config.new_build_error(
                ("metrics.alerts", id_str, "notify.email.body"),
                "Missing email body",
            );
        }

        alert.method.push(AlertMethod::Email {
            from_name,
            from_addr,
            to,
            subject,
            body,
        });
    }

    if alert.method.is_empty() {
        config.new_build_error(
            ("metrics.alerts", id_str),
            "No notification method enabled for alert",
        );
    }

    alert.into()
}

fn parse_alert_content(key: impl AsKey, config: &mut Config) -> Option<AlertContent> {
    let mut tokens = Vec::new();
    let mut value = config.value(key)?.chars().peekable();
    let mut buf = String::new();

    while let Some(ch) = value.next() {
        if ch == '%' && value.peek() == Some(&'{') {
            value.next();

            let mut var_name = String::new();
            let mut found_curly = false;

            for ch in value.by_ref() {
                if ch == '}' {
                    found_curly = true;
                    break;
                }
                var_name.push(ch);
            }

            if found_curly && value.peek() == Some(&'%') {
                value.next();
                if let Some(event_type) = EventType::try_parse(&var_name)
                    .map(AlertContentToken::Event)
                    .or_else(|| MetricType::try_parse(&var_name).map(AlertContentToken::Metric))
                {
                    if !buf.is_empty() {
                        tokens.push(AlertContentToken::Text(std::mem::take(&mut buf)));
                    }
                    tokens.push(event_type);
                } else {
                    buf.push('%');
                    buf.push('{');
                    buf.push_str(&var_name);
                    buf.push('}');
                    buf.push('%');
                }
            } else {
                buf.push('%');
                buf.push('{');
                buf.push_str(&var_name);
            }
        } else {
            buf.push(ch);
        }
    }

    if !buf.is_empty() {
        tokens.push(AlertContentToken::Text(buf));
    }

    AlertContent(tokens).into()
}

fn sanitize_metric_name(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            result.push(ch);
        } else {
            result.push('_');
        }
    }

    result
}

