"""This package holds the rules of the policy, as mixins of Policy, grouped by what they judge.

Contents:
- servicerules: the keys of a service, each harmless or checked, so the policy refuses an unknown key
- projectrules: the project as a whole: where it is, its name, its networks, volumes, secrets and configs
- buildrules: what a build can reach: compose build sections and bake definitions
- userrules: the users of services and images, and the changes that pin them
- idrules: the uids and gids those users may have, and the facts the rules judge them by (IdFacts)
- useroptionrules: the users that a command line gives
- base: what the mixins share

Not here: the settings that the rules apply, which Policy holds. Not here either: code that calls the
rules in order; that is the job of Policy (policy.policy) and of screen.

Constraints: as for policy. A rule returns what it finds; it does not print, raise for a refusal, or call
docker. The rules do not depend on the modules that describe their results (userdecisionview).

Dependencies: as for policy. The mixins use each other only through Policy, except that UserRules extends
IdRules, whose rules it applies.
"""
