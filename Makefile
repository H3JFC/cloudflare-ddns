.DEFAULT_GOAL := help
.NOTPARALLEL:

BUMP_SCRIPT := scripts/bump.sh
BUMP_TYPES  := patch minor major

BUMP_TARGETS := $(addprefix bump-,$(BUMP_TYPES))

.PHONY: help version deps build test check-clean git-tag $(BUMP_TARGETS)

# ---------------------------------------------------------------------------
# Pretty-printing helpers
#
# Usage inside a recipe:  @$(call log_info,Doing a thing)
#                         @$(call log_error,Something broke)   # exits non-zero
#
# These are deliberately NOT named info/warning/error: GNU make always runs
# its built-in function of that name when called via $(call ...), which would
# print or abort at parse time instead of running the shell command.
#
# Colors are disabled when NO_COLOR is set or stderr is not a terminal.
# ---------------------------------------------------------------------------
ifndef NO_COLOR
ifeq ($(shell [ -t 2 ] && echo yes),yes)
C_RED    := \033[31m
C_GREEN  := \033[32m
C_YELLOW := \033[33m
C_BLUE   := \033[34m
C_BOLD   := \033[1m
C_RESET  := \033[0m
endif
endif

log_info    = printf '$(C_BLUE)[info]$(C_RESET)  %s\n' "$(1)"
log_success = printf '$(C_GREEN)[ ok ]$(C_RESET)  %s\n' "$(1)"
log_warn    = printf '$(C_YELLOW)[warn]$(C_RESET)  %s\n' "$(1)" >&2
log_error   = printf '$(C_RED)[fail]$(C_RESET)  %s\n' "$(1)" >&2; exit 1

# Current [package] version from Cargo.toml. Recursive (lazy) so it is read
# when a recipe runs, i.e. after any bump prerequisites have finished.
VERSION = $(shell awk '/^\[/ { p = ($$0 ~ /^\[package\][[:space:]]*$$/) } \
	p && /^version[[:space:]]*=/ { match($$0, /"[^"]+"/); \
	print substr($$0, RSTART + 1, RLENGTH - 2); exit }' Cargo.toml)

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
help: ## Show this help
	@printf '$(C_BOLD)Targets:$(C_RESET)\n'
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk -F ':.*## ' '{ printf "  %-18s %s\n", $$1, $$2 }'
	@printf '  %-18s %s\n' 'bump-patch|minor|major' 'Bump version, refresh lockfile, run tests'

version: ## Print the current Cargo.toml version
	@echo $(VERSION)

deps: ## Fetch dependencies
	@$(call log_info,Fetching dependencies)
	@cargo fetch
	@$(call log_success,Dependencies fetched)

build: ## Build release binary (uses Cargo.lock as-is)
	@$(call log_info,Building release binary)
	@cargo build --release --locked
	@$(call log_success,Build complete)

test: ## Run tests (uses Cargo.lock as-is)
	@$(call log_info,Running tests)
	@cargo test --locked
	@$(call log_success,Tests passed)

check-clean:
	@if [ -n "$$(git status --porcelain --untracked-files=no)" ]; then \
		$(call log_error,Working tree has uncommitted changes to tracked files - commit or stash them first); \
	fi

# bump-patch / bump-minor / bump-major
# Bumps Cargo.toml, regenerates the lockfile and runs the tests (see the script,
# which prints the old and new versions itself).
$(BUMP_TARGETS): bump-%:
	@$(call log_info,Bumping $* version)
	@$(BUMP_SCRIPT) $* || { $(call log_error,Bump failed - Cargo.toml and Cargo.lock were restored); }

git-tag: ## Tag HEAD as v<Cargo.toml version> (no bump, no push)
	@if [ -z "$(VERSION)" ]; then \
		$(call log_error,Could not read version from Cargo.toml); \
	fi
	@if git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null; then \
		$(call log_error,Tag v$(VERSION) already exists); \
	fi
	@git tag -a "v$(VERSION)" -m "v$(VERSION)"
	@$(call log_success,Tagged HEAD as v$(VERSION))
	@$(call log_warn,Not pushed - run: git push origin v$(VERSION))
