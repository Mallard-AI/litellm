use std::{sync::Arc, time::SystemTime};

use fancy_regex::Regex;

use crate::AccessRequest;
pub use crate::error::{Denial, PolicyConstructionError};

const ALL_PROXY_MODELS: &str = "all-proxy-models";
const ALL_TEAM_MODELS: &str = "all-team-models";

#[derive(Clone, Debug)]
enum ModelPattern {
    Exact(String),
    Regex(Regex),
}

impl ModelPattern {
    fn new(pattern: String) -> Result<Self, PolicyConstructionError> {
        if !pattern.contains('*') {
            return Ok(Self::Exact(pattern));
        }
        let expression = format!("^{}$", pattern.replace('*', ".*"));
        let regex = Regex::new(&expression).map_err(|source| {
            PolicyConstructionError::InvalidModelPattern {
                pattern: pattern.clone(),
                detail: source.to_string(),
            }
        })?;
        Ok(Self::Regex(regex))
    }

    fn matches(&self, model: &str) -> bool {
        match self {
            Self::Exact(pattern) => pattern == model,
            Self::Regex(regex) => regex.is_match(model).unwrap_or(false),
        }
    }
}

#[derive(Clone, Debug)]
enum ModelScopeKind {
    Unrestricted,
    Patterns(Arc<[ModelPattern]>),
    ExpandedEmpty,
    AllTeamModels,
}

#[derive(Clone, Debug)]
pub struct ModelScope(ModelScopeKind);

impl ModelScope {
    pub fn unrestricted() -> Self {
        Self(ModelScopeKind::Unrestricted)
    }

    pub fn patterns<I, S>(patterns: I) -> Result<Self, PolicyConstructionError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let patterns: Vec<String> = patterns.into_iter().map(Into::into).collect();
        if patterns.is_empty() {
            return Ok(Self::unrestricted());
        }
        let has_all_team_models = patterns.iter().any(|pattern| pattern == ALL_TEAM_MODELS);
        let has_all_proxy_models = patterns.iter().any(|pattern| pattern == ALL_PROXY_MODELS);
        let patterns: Result<Vec<ModelPattern>, PolicyConstructionError> =
            patterns.into_iter().map(ModelPattern::new).collect();
        let patterns = patterns?;
        if has_all_team_models {
            return Ok(Self(ModelScopeKind::AllTeamModels));
        }
        if has_all_proxy_models {
            return Ok(Self::unrestricted());
        }
        Ok(Self(ModelScopeKind::Patterns(patterns.into())))
    }

    /// Builds a model scope from caller-resolved model names and access groups.
    ///
    /// The caller must resolve provider aliases and access groups before construction. This helper does not provide full runtime resolver parity.
    pub fn expanded<I, S>(models: I) -> Result<Self, PolicyConstructionError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let models: Vec<String> = models.into_iter().map(Into::into).collect();
        if models.is_empty() {
            return Ok(Self(ModelScopeKind::ExpandedEmpty));
        }
        if models
            .iter()
            .any(|model| model == ALL_PROXY_MODELS || model == ALL_TEAM_MODELS)
        {
            return Err(PolicyConstructionError::UnsupportedModelSentinel);
        }
        let patterns: Result<Vec<ModelPattern>, PolicyConstructionError> =
            models.into_iter().map(ModelPattern::new).collect();
        Ok(Self(ModelScopeKind::Patterns(patterns?.into())))
    }

    pub fn is_all_team_models(&self) -> bool {
        matches!(self.0, ModelScopeKind::AllTeamModels)
    }

    fn allows(&self, model: &str) -> bool {
        match &self.0 {
            ModelScopeKind::Unrestricted => true,
            ModelScopeKind::ExpandedEmpty => false,
            ModelScopeKind::AllTeamModels => false,
            ModelScopeKind::Patterns(patterns) => {
                patterns.iter().any(|pattern| pattern.matches(model))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct TeamPolicy {
    models: ModelScope,
    aliases: Arc<[String]>,
    blocked: bool,
}

impl TeamPolicy {
    pub fn new(models: ModelScope) -> Result<Self, PolicyConstructionError> {
        if models.is_all_team_models() {
            return Err(PolicyConstructionError::UnsupportedModelSentinel);
        }
        Ok(Self {
            models,
            aliases: Arc::default(),
            blocked: false,
        })
    }

    pub fn with_aliases<I, S>(mut self, aliases: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        // Python parity: a team alias is granted only when present in the resolved alias map (auth_checks.py:5167-5191, 2026-10-25).
        self.aliases = aliases
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>()
            .into();
        self
    }

    pub fn blocked(mut self, blocked: bool) -> Self {
        self.blocked = blocked;
        self
    }

    fn allows(&self, model: &str) -> bool {
        self.models.allows(model) || self.allows_alias(model)
    }

    fn allows_alias(&self, model: &str) -> bool {
        self.aliases.iter().any(|alias| alias == model)
    }
}

#[derive(Clone, Debug)]
enum RoutePattern {
    Literal(String),
    WildcardPrefix(String),
}

impl RoutePattern {
    fn new(pattern: String) -> Result<Self, PolicyConstructionError> {
        if pattern.is_empty() || pattern.contains('{') || pattern.contains('}') {
            return Err(PolicyConstructionError::UnsupportedRoutePattern(pattern));
        }
        if pattern != "*" && !pattern.starts_with('/') {
            return Err(PolicyConstructionError::UnsupportedRoutePattern(pattern));
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return Ok(Self::WildcardPrefix(prefix.to_owned()));
        }
        if pattern.contains('*') {
            return Err(PolicyConstructionError::UnsupportedRoutePattern(pattern));
        }
        Ok(Self::Literal(pattern))
    }

    fn matches(&self, route: &str) -> bool {
        match self {
            Self::Literal(path) => route == path || route.starts_with(&format!("{path}/")),
            Self::WildcardPrefix(prefix) => route.starts_with(prefix),
        }
    }
}

#[derive(Clone, Debug)]
enum RouteScopeKind {
    Unrestricted,
    ExpandedEmpty,
    Patterns(Arc<[RoutePattern]>),
}

#[derive(Clone, Debug)]
pub struct RouteScope(RouteScopeKind);

impl RouteScope {
    pub fn unrestricted() -> Self {
        Self(RouteScopeKind::Unrestricted)
    }

    pub fn allowed<I, S>(routes: I) -> Result<Self, PolicyConstructionError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let routes: Result<Vec<RoutePattern>, PolicyConstructionError> = routes
            .into_iter()
            .map(|route| RoutePattern::new(route.into()))
            .collect();
        let routes = routes?;
        if routes.is_empty() {
            return Ok(Self::unrestricted());
        }
        Ok(Self(RouteScopeKind::Patterns(routes.into())))
    }

    /// Builds a route scope from caller-expanded named route groups.
    ///
    /// The caller must resolve named route groups before construction. This helper does not provide full runtime resolver parity.
    pub fn expanded<I, S>(routes: I) -> Result<Self, PolicyConstructionError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let routes: Result<Vec<RoutePattern>, PolicyConstructionError> = routes
            .into_iter()
            .map(|route| RoutePattern::new(route.into()))
            .collect();
        let routes = routes?;
        if routes.is_empty() {
            return Ok(Self(RouteScopeKind::ExpandedEmpty));
        }
        Ok(Self(RouteScopeKind::Patterns(routes.into())))
    }

    fn allows(&self, route: &str) -> bool {
        match &self.0 {
            RouteScopeKind::Unrestricted => true,
            RouteScopeKind::ExpandedEmpty => false,
            RouteScopeKind::Patterns(patterns) => {
                patterns.iter().any(|pattern| pattern.matches(route))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeyPolicy {
    key_models: ModelScope,
    team: Option<TeamPolicy>,
    user_models: Option<ModelScope>,
    member_models: Option<ModelScope>,
    blocked: bool,
    expires_at: Option<SystemTime>,
    routes: RouteScope,
}

impl KeyPolicy {
    pub fn new(
        key_models: ModelScope,
        team: Option<TeamPolicy>,
        user_models: Option<ModelScope>,
        member_models: Option<ModelScope>,
        blocked: bool,
        expires_at: Option<SystemTime>,
        routes: RouteScope,
    ) -> Result<Self, PolicyConstructionError> {
        if team
            .as_ref()
            .is_some_and(|team| team.models.is_all_team_models())
        {
            return Err(PolicyConstructionError::UnsupportedModelSentinel);
        }
        Ok(Self {
            key_models,
            team,
            user_models,
            member_models,
            blocked,
            expires_at,
            routes,
        })
    }

    pub fn unrestricted() -> Self {
        Self {
            key_models: ModelScope::unrestricted(),
            team: None,
            user_models: None,
            member_models: None,
            blocked: false,
            expires_at: None,
            routes: RouteScope::unrestricted(),
        }
    }

    pub fn check(&self, request: &AccessRequest, now: SystemTime) -> Result<(), Denial> {
        if matches!(request, AccessRequest::Mcp { .. } | AccessRequest::Ui(_)) {
            return Err(Denial::UnsupportedRequest);
        }
        if self.expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Err(Denial::Expired);
        }
        if self.blocked {
            return Err(Denial::KeyBlocked);
        }
        if self.team.as_ref().is_some_and(|team| team.blocked) {
            return Err(Denial::TeamBlocked);
        }
        match request {
            AccessRequest::Route { path, .. } => {
                if self.routes.allows(path) {
                    Ok(())
                } else {
                    Err(Denial::RouteDenied)
                }
            }
            AccessRequest::Model { name, .. } => {
                let key_models = if self.key_models.is_all_team_models() {
                    self.team
                        .as_ref()
                        .map_or(ModelScope::unrestricted(), |team| team.models.clone())
                } else {
                    self.key_models.clone()
                };
                // Python parity: resolved team aliases participate in key model access checks (auth_checks.py:4970-4984, 2026-10-25).
                let allows_team_alias = !matches!(self.key_models.0, ModelScopeKind::ExpandedEmpty)
                    && self
                        .team
                        .as_ref()
                        .is_some_and(|team| team.allows_alias(name));
                if !key_models.allows(name) && !allows_team_alias {
                    return Err(Denial::KeyModelDenied);
                }
                if let Some(team) = &self.team
                    && !team.allows(name)
                {
                    return Err(Denial::TeamModelDenied);
                }
                if self
                    .user_models
                    .as_ref()
                    .is_some_and(|models| !models.allows(name))
                {
                    return Err(Denial::UserModelDenied);
                }
                if self
                    .member_models
                    .as_ref()
                    .is_some_and(|models| !models.allows(name))
                {
                    return Err(Denial::MemberModelDenied);
                }
                Ok(())
            }
            AccessRequest::Mcp { .. } | AccessRequest::Ui(_) => Err(Denial::UnsupportedRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use rstest::{fixture, rstest};

    use crate::{McpAction, UiAction};

    use super::*;

    #[fixture]
    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000)
    }

    fn model_request(name: &str) -> AccessRequest {
        AccessRequest::Model {
            name: name.to_owned(),
            deployment: "resolved-by-caller".to_owned(),
        }
    }

    #[rstest]
    #[case::key_and_team_intersection("gpt-4o", Denial::TeamModelDenied)]
    #[case::key_denial("claude-3", Denial::KeyModelDenied)]
    fn model_scopes_intersect(#[case] name: &str, #[case] denial: Denial, now: SystemTime) {
        let key = ModelScope::patterns(["gpt-*"]).expect("valid key scope");
        let team = TeamPolicy::new(ModelScope::patterns(["claude-*"]).expect("valid team scope"))
            .expect("valid team");
        let policy = KeyPolicy::new(
            key,
            Some(team),
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");

        assert_eq!(policy.check(&model_request(name), now), Err(denial));
    }

    #[rstest]
    fn model_pattern_uses_python_regex_semantics(now: SystemTime) {
        let policy = KeyPolicy::new(
            ModelScope::patterns(["gpt-4.o*"]).expect("valid regex pattern"),
            None,
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(policy.check(&model_request("gpt-4ao-fine"), now), Ok(()));
    }

    #[rstest]
    #[case::all_proxy("gpt-4o", vec!["all-proxy-models"])]
    #[case::empty_input("gpt-4o", Vec::<&str>::new())]
    fn unrestricted_sentinels_allow(
        #[case] name: &str,
        #[case] models: Vec<&str>,
        now: SystemTime,
    ) {
        let policy = KeyPolicy::new(
            ModelScope::patterns(models).expect("valid scope"),
            None,
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(policy.check(&model_request(name), now), Ok(()));
    }

    #[rstest]
    fn all_team_models_replaces_key_list(now: SystemTime) {
        let team = TeamPolicy::new(ModelScope::patterns(["gpt-*"]).expect("valid team scope"))
            .expect("valid team");
        let policy = KeyPolicy::new(
            ModelScope::patterns(["all-team-models"]).expect("valid sentinel"),
            Some(team),
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(policy.check(&model_request("gpt-4o"), now), Ok(()));
        assert_eq!(
            policy.check(&model_request("claude-3"), now),
            Err(Denial::KeyModelDenied)
        );
    }

    #[rstest]
    fn all_team_models_without_team_are_unrestricted(now: SystemTime) {
        let policy = KeyPolicy::new(
            ModelScope::patterns(["all-team-models"]).expect("valid sentinel"),
            None,
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(policy.check(&model_request("gpt-4o"), now), Ok(()));
    }

    #[rstest]
    fn aliases_match_only_caller_supplied_alias_names(now: SystemTime) {
        let team = TeamPolicy::new(ModelScope::expanded(["gpt-4o"]).expect("valid team scope"))
            .expect("valid team")
            .with_aliases(["team-alias"]);
        let policy = KeyPolicy::new(
            ModelScope::unrestricted(),
            Some(team),
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(policy.check(&model_request("team-alias"), now), Ok(()));
        assert_eq!(
            policy.check(&model_request("resolved-by-caller"), now),
            Err(Denial::TeamModelDenied)
        );
    }

    #[rstest]
    fn restricted_key_accepts_team_alias_without_bypassing_member_scope(now: SystemTime) {
        let team = TeamPolicy::new(ModelScope::patterns(["team-*"]).expect("valid team scope"))
            .expect("valid team")
            .with_aliases(["team-alias"]);
        let policy = KeyPolicy::new(
            ModelScope::patterns(["key-*"]).expect("valid key scope"),
            Some(team.clone()),
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(policy.check(&model_request("team-alias"), now), Ok(()));
        assert_eq!(
            policy.check(&model_request("unknown-alias"), now),
            Err(Denial::KeyModelDenied)
        );

        let restricted = KeyPolicy::new(
            ModelScope::patterns(["key-*"]).expect("valid key scope"),
            Some(team),
            None,
            Some(ModelScope::expanded(["member-*"]).expect("member scope")),
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(
            restricted.check(&model_request("team-alias"), now),
            Err(Denial::MemberModelDenied)
        );
    }

    #[rstest]
    fn all_team_models_inherits_team_aliases(now: SystemTime) {
        let team = TeamPolicy::new(ModelScope::patterns(["team-*"]).expect("valid team scope"))
            .expect("valid team")
            .with_aliases(["team-alias"]);
        let policy = KeyPolicy::new(
            ModelScope::patterns(["all-team-models"]).expect("valid sentinel"),
            Some(team),
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(policy.check(&model_request("team-alias"), now), Ok(()));
    }

    #[rstest]
    fn expanded_empty_key_scope_rejects_team_alias(now: SystemTime) {
        let team = TeamPolicy::new(ModelScope::patterns(["team-*"]).expect("valid team scope"))
            .expect("valid team")
            .with_aliases(["team-alias"]);
        let policy = KeyPolicy::new(
            ModelScope::expanded(Vec::<&str>::new()).expect("empty expansion"),
            Some(team),
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(
            policy.check(&model_request("team-alias"), now),
            Err(Denial::KeyModelDenied)
        );
    }

    #[rstest]
    fn user_scope_intersects_key(now: SystemTime) {
        let policy = KeyPolicy::new(
            ModelScope::unrestricted(),
            None,
            Some(ModelScope::expanded(["gpt-4o"]).expect("user scope")),
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(
            policy.check(&model_request("claude-3"), now),
            Err(Denial::UserModelDenied)
        );
    }

    #[rstest]
    fn non_empty_member_scope_intersects_key(now: SystemTime) {
        let policy = KeyPolicy::new(
            ModelScope::unrestricted(),
            None,
            None,
            Some(ModelScope::expanded(["gpt-4o"]).expect("member scope")),
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(
            policy.check(&model_request("claude-3"), now),
            Err(Denial::MemberModelDenied)
        );
    }

    #[rstest]
    fn empty_member_scope_does_not_restrict(now: SystemTime) {
        let team = TeamPolicy::new(ModelScope::patterns(["gpt-*"]).expect("valid team scope"))
            .expect("valid team");
        let member = ModelScope::patterns(Vec::<&str>::new()).expect("empty scope");
        let policy = KeyPolicy::new(
            ModelScope::unrestricted(),
            Some(team),
            None,
            Some(member),
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(policy.check(&model_request("gpt-4o"), now), Ok(()));
    }

    #[rstest]
    fn expanded_empty_member_scope_denies(now: SystemTime) {
        let policy = KeyPolicy::new(
            ModelScope::unrestricted(),
            None,
            None,
            Some(ModelScope::expanded(Vec::<&str>::new()).expect("empty expansion")),
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(
            policy.check(&model_request("gpt-4o"), now),
            Err(Denial::MemberModelDenied)
        );
    }

    #[rstest]
    fn expanded_empty_key_scope_denies(now: SystemTime) {
        let policy = KeyPolicy::new(
            ModelScope::expanded(Vec::<&str>::new()).expect("empty expansion"),
            None,
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(
            policy.check(&model_request("gpt-4o"), now),
            Err(Denial::KeyModelDenied)
        );
    }

    #[rstest]
    #[case::configured_empty(
        RouteScope::allowed(Vec::<&str>::new()).expect("empty configured routes"),
        Ok(())
    )]
    #[case::expanded_empty(
        RouteScope::expanded(Vec::<&str>::new()).expect("empty expanded routes"),
        Err(Denial::RouteDenied)
    )]
    fn empty_route_scopes_preserve_resolution_semantics(
        #[case] routes: RouteScope,
        #[case] expected: Result<(), Denial>,
        now: SystemTime,
    ) {
        let policy = KeyPolicy::new(
            ModelScope::unrestricted(),
            None,
            None,
            None,
            false,
            None,
            routes,
        )
        .expect("valid policy");
        assert_eq!(
            policy.check(
                &AccessRequest::Route {
                    method: "POST".to_owned(),
                    path: "/v1/chat/completions".to_owned()
                },
                now
            ),
            expected
        );
    }

    #[rstest]
    fn route_prefix_obeys_boundary(now: SystemTime) {
        let policy = KeyPolicy::new(
            ModelScope::unrestricted(),
            None,
            None,
            None,
            false,
            None,
            RouteScope::allowed(["/v1/chat"]).expect("valid route"),
        )
        .expect("valid policy");
        assert_eq!(
            policy.check(
                &AccessRequest::Route {
                    method: "POST".to_owned(),
                    path: "/v1/chat/completions".to_owned()
                },
                now
            ),
            Ok(())
        );
        assert_eq!(
            policy.check(
                &AccessRequest::Route {
                    method: "POST".to_owned(),
                    path: "/v1/chatter".to_owned()
                },
                now
            ),
            Err(Denial::RouteDenied)
        );
    }

    #[rstest]
    fn wildcard_route_matches_python_prefix(now: SystemTime) {
        let policy = KeyPolicy::new(
            ModelScope::unrestricted(),
            None,
            None,
            None,
            false,
            None,
            RouteScope::allowed(["/v1/chat*"]).expect("valid route"),
        )
        .expect("valid policy");
        assert_eq!(
            policy.check(
                &AccessRequest::Route {
                    method: "POST".to_owned(),
                    path: "/v1/chatter".to_owned()
                },
                now
            ),
            Ok(())
        );
    }

    #[rstest]
    fn blocked_expired_and_unsupported_fail_closed(now: SystemTime) {
        let blocked = KeyPolicy::new(
            ModelScope::unrestricted(),
            None,
            None,
            None,
            true,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(
            blocked.check(&model_request("gpt-4o"), now),
            Err(Denial::KeyBlocked)
        );

        let blocked_team = TeamPolicy::new(ModelScope::unrestricted())
            .expect("valid team")
            .blocked(true);
        let team_blocked_policy = KeyPolicy::new(
            ModelScope::unrestricted(),
            Some(blocked_team),
            None,
            None,
            false,
            None,
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(
            team_blocked_policy.check(&model_request("gpt-4o"), now),
            Err(Denial::TeamBlocked)
        );

        let expired = KeyPolicy::new(
            ModelScope::unrestricted(),
            None,
            None,
            None,
            false,
            Some(now),
            RouteScope::unrestricted(),
        )
        .expect("valid policy");
        assert_eq!(
            expired.check(&model_request("gpt-4o"), now),
            Err(Denial::Expired)
        );

        let unsupported = KeyPolicy::unrestricted();
        assert_eq!(
            unsupported.check(
                &AccessRequest::Mcp {
                    server: "server".to_owned(),
                    action: McpAction::Connect
                },
                now
            ),
            Err(Denial::UnsupportedRequest)
        );
        assert_eq!(
            unsupported.check(&AccessRequest::Ui(UiAction::Logout), now),
            Err(Denial::UnsupportedRequest)
        );
    }

    #[rstest]
    fn unsupported_patterns_fail_construction() {
        assert!(matches!(
            ModelScope::patterns(["[*"]),
            Err(PolicyConstructionError::InvalidModelPattern { .. })
        ));
        assert!(matches!(
            RouteScope::allowed(["/threads/{id}"]),
            Err(PolicyConstructionError::UnsupportedRoutePattern(_))
        ));
        assert!(matches!(
            RouteScope::allowed(["/v1/ch*t"]),
            Err(PolicyConstructionError::UnsupportedRoutePattern(_))
        ));
        assert!(matches!(
            RouteScope::allowed(["chat-completions"]),
            Err(PolicyConstructionError::UnsupportedRoutePattern(_))
        ));
        assert!(matches!(
            ModelScope::expanded(["all-proxy-models"]),
            Err(PolicyConstructionError::UnsupportedModelSentinel)
        ));
    }
}
