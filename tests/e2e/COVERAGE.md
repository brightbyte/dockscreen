# What the end-to-end tests do not reach

Audience: whoever changes dockscreen's checks and reads the coverage report of
`DOCKSCREEN_E2E_COVERAGE=1 pytest -m e2e`. Every line and branch of dockscreen that the scenarios do not
reach should be listed here, with the reason. Anything missing from the report and from this list is a
gap: write a scenario for it.

The unit tests cover what is listed, unless it says otherwise.

## Defences that a real docker or compose never triggers

They guard against a docker, compose or buildx that behaves differently from today's, and fail closed.

- `projectscreening._read_back_problem` and `_first_difference`: compose reading the generated file back
  differently from what was checked. dockscreen writes compose's own output, so today's compose reads it
  back the same.
- `inspect._load_config`: `docker compose config` printing something that is not JSON.
- `docker_bake._definition`: `bake --print` printing something that is not a JSON object.
- `build.fields` for entries given as text, and `Policy._check_cache_from` for an entry it cannot read:
  current buildx prints `output`, `cache-from`, `cache-to` and `secret` entries as objects. Older buildx
  prints text.
- `serviceusers._services_to_run`: `docker compose config --services` failing after `config` worked.
- `dockerclient.label_values` and `inspect.name_conflicts`: `docker ps` failing.
- `dockerclient._first_file_of_tar`: `docker cp` sending something that is not a tar archive.
- `Policy.check_project`: a config without a project name; compose always gives one. `_check_scope`
  without a project name, likewise.
- `policy.unknown_keys` for top-level keys: compose refuses unknown top-level keys itself, and leaves
  out the ones it knows but does not use (`models`).
- `Policy.check_cap_drop` and `check_security_opt` refusing a missing ALL or no-new-privileges, and
  `compose_harden._fix_config` adding them: hardening adds both to every service before the policy sees
  it.
- `policy._check_host_files` for an `env_file` entry without a path: compose gives every entry one.
- `compose_lifecycle.check` for a project without a name.
- `Policy.check_user` for a service without a user: the services that set none are left to their
  images, and those that start get a user before the final check.
- `decisions.Decisions.changes` for a decision that pins no user: a refused or failed decision stops
  the run before finalize.
- `docker_run._verify_split` refusing a command line whose image dockscreen misread: it knows every
  value-taking option of `docker run` that the daemon accepts on Linux. An option it does not know, such
  as `--cpu-count`, fails at `create` instead
  (`test_an_option_dockscreen_does_not_know_fails_closed`).
- `x-` keys in a compose `build`: compose drops them from its config, and its own build ignores them
  (`test_compose_drops_x_bake_from_a_build_so_its_output_is_never_written`). `docker buildx bake` reads
  `x-bake` from a compose file, and is screened on what `--print` gives.

## Races

Something has to change between two of dockscreen's calls to docker.

- `docker_run._create_checked` refusing the container created again with the pinned user.
- `docker_run.check` failing to inspect the container it just created, or its image.
- `serviceusers._decide` failing to inspect the container it just created.
- `config._read`: the config file replaced between the check of its modes and the read.
- `dockerclient.run_child`: docker vanishing between dockscreen's first call and compose.

## Signals and terminals

- `dockerclient.run_child` passing SIGTERM, SIGHUP and SIGQUIT on to compose, and waiting through Ctrl-C:
  the hand-off returns at once, so there is nothing to signal.
- `messages`: wrapping report lines to the terminal and colouring the marks. The tests run without a
  terminal, with `NO_COLOR` and `COLUMNS=10`.

## Not reachable from the command line

- `Docker.new_for_testing`, `Subordinate.new_for_testing`, `runtime._real_docker` with wrappers given,
  `config.effective` without a directory: for the unit tests.
- `imageuser.describe` without the host's accounts.
- `messages._escape` for a character above U+FFFF: the messages that quote project text with one in it
  quote it with `repr`, which escapes it first (`test_characters_beyond_the_basic_plane_are_shown_as_text`).
- `policy._outside` without a config file to name in the hint: dockscreen always knows where the
  caller's file is.
- `images.section_hint` for an image from a registry other than Docker Hub: the scenarios pull only from
  Docker Hub.
- `docker_cli`'s `if __name__ == "__main__"`: `bin/docker` calls `main` itself.
- `commandline.CommandLine` and `find_subcommand` at a `--` before the command (`docker -- ps`), and
  `option_value` at a `--` before `--pull`.
- `docker_run.audit` when docker is missing: the check for a remote daemon runs docker first, and the
  entry point reports that it is missing.

## Depends on the host

- `inspect._find_compose_dir` refusing a compose file in the home directory or a directory that is not
  yours, and reaching `/` without one: the tests would have to put a compose file in your home or in a
  directory of another user.
- `config._strict_modes` for a file or directory owned by another user: the tests run as one user.
- `config.user_file` without an absolute `XDG_CONFIG_HOME`: dockscreen would read your own config file.
- `hostusers._read_ranges` for a missing `/etc/subuid` or a malformed line in it.
- The scenarios that need a user 101, or none, an account with uid 1, or a subordinate range are skipped
  where the host does not have them (see the README).

## Depends on the image store

With docker's containerd image store, which these tests ran against, a locally tagged or built image
has a repo digest under its local name (`docs/security-review.md`). So these are not reached:

- `config.section_for` saying that the image was not pulled from the section's repository, and the note
  in the report of `docker_run.audit` that says so.
- `serviceusers._find_section_images` and `Scope.project_policy` finding no proof for a section, and the final check of
  `projectscreening.check_and_run` refusing a service that only passed because of it.

The scenarios for them are marked as expected failures.
