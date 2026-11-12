"""This package holds the rules of the policy, as mixins of Policy, grouped by what they judge.

Contents:
- servicerules: the keys of a service, each harmless or checked, so an unknown key is refused
- projectrules: the project as a whole: where it is, its name, its networks, volumes, secrets and configs
- buildrules: what a build can reach: compose build sections and bake definitions
- userrules: users and ids, and the facts they are judged by (IdFacts)
- base: what the mixins share

Not here: the settings the rules apply with, which Policy holds, and anything that calls them in order;
that is Policy's (policy.policy) and screen's.

Constraints: as for policy. A rule returns what it finds; it does not print, raise for a refusal, or call
docker. How a decision is put into words for the reader is not a rule's (userdecisionview).

Exceptions: userrules takes wording from userdecisionview (CHOOSE_HINT, instead_of_root), so the rules
depend on the module that describes their results.

Dependencies: as for policy. The mixins use each other only through Policy.
"""
