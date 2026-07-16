"""
guard_selection_271.py

Simplified implementation of Tor's Proposal 271 guard selection algorithm
(guard-spec.txt, Tor >= 0.3.0.1-alpha).

Written to replace pathsim.py's old guard-related functions (get_new_guard,
filter_guards, get_guards_for_circ). The old pathsim.py guard logic follows
the pre-0.3.0 model based on choose_random_entry_impl() / pick_entry_guards(),
which immediately adds a new guard to the list whenever a guard becomes
unusable, without any judgment call - i.e. it still has the "guard churn"
pattern. This module instead reflects the SAMPLED -> FILTERED -> PRIMARY
three-tier hierarchy and confirmed-guard priority ordering.

Notes on simplifications made here (keep in mind when validating accuracy):
  - The "internet likely down" heuristic (treating simultaneous guard
    failures as a client-side network problem rather than a guard problem)
    is omitted. Implementing it would require client-wide network-state
    tracking, i.e. extending pathsim's client_state structure.
  - Bridge-related logic is excluded (only regular relay guards are
    handled).
  - Primary guard retry backoff reuses pathsim.py's existing
    guard_is_time_to_retry() as-is (this logic has in fact been retained
    even after Prop271, so reuse is valid).
  - NUM_PRIMARY_GUARDS (guard-n-primary-guards) defaults to 3, but the
    number actually "considered" when building a circuit
    (NUM_PRIMARY_GUARDS_TO_USE, guard-n-primary-guards-to-use) has a
    param-spec-documented default of 1; however, the real network has
    been running with 2 (via Directory Authority vote) since 2022-07 -
    see the comment on GuardSelectionOptions.NUM_PRIMARY_GUARDS_TO_USE
    below.

Original C implementation reference: src/feature/client/entrynodes.c
Spec reference: https://spec.torproject.org/guard-spec/
"""

from __future__ import print_function
import logging
from collections import OrderedDict
from random import choice

logger = logging.getLogger(__name__)

# Cache for get_max_sample_size()'s eligible-guard count: this depends only
# on the current consensus, not on any particular client's sampled-guard
# state, so it's shared across every GuardSelectionState instance instead
# of each client (there can be thousands, under --user_model all)
# redundantly re-scanning every relay for itself. Keyed on
# id(cons_rel_stats), tracking only the single most-recent period for the
# same reasons as pathsim.py's _exit_cache (avoids unbounded growth and
# stale id() reuse collisions).
_n_eligible_cache = [None, None]  # [period_key, n_eligible]


class GuardSelectionOptions(object):
    """Approximation of guard-spec.txt Section 2. Split out as constants so
    they can be overridden with real consensus parameters."""

    # Number of guards to try first when building a circuit.
    NUM_PRIMARY_GUARDS = 3

    # Number of primary guards actually "considered" for this circuit -
    # a random choice is made among these. param-spec.txt's *documented*
    # default is 1, but the real network has been overridden by Directory
    # Authority vote to 2 since 2022-07 (Roger Dingledine, tor-relays
    # mailing list, 2022-07-06: "we're trying out
    # guard-n-primary-guards-to-use=2" - this is the value settled on, as
    # foreshadowed in Proposal 291). In other words, the spec-document
    # default and the actual deployed value differ here, so to simulate
    # a current-day network we should use the deployed value (2), not the
    # spec default (1).
    NUM_PRIMARY_GUARDS_TO_USE = 2

    # If FILTERED_GUARDS drops below this count, expand SAMPLED_GUARDS.
    MIN_FILTERED_SAMPLE_SIZE = 20

    # [B3] Absolute cap on SAMPLED_GUARDS size (param-spec:
    # guard-max-sample-size, default 60 - confirmed).
    MAX_SAMPLE_SIZE_ABSOLUTE = 60

    # [B3] Cap on SAMPLED_GUARDS size as a fraction of the total number of
    # eligible guards in the current consensus (param-spec:
    # guard-max-sample-threshold-percent, default 20% - confirmed). Despite
    # the param-spec wording ("bandwidth-weighted fraction"), the actual
    # C implementation (get_max_sample_size() in entrynodes.c) multiplies
    # this by a plain eligible-guard *count*, not a bandwidth-weighted
    # value - we mirror that actual behavior here, not the doc wording.
    MAX_SAMPLE_THRESHOLD_PERCENT = 0.20

    # Remove entirely from SAMPLED_GUARDS if absent from the consensus for
    # this long (param-spec: guard-remove-unlisted-guards-after-days,
    # default 20 days - confirmed against param-spec.txt).
    REMOVE_UNLISTED_GUARDS_AFTER = 20 * 24 * 3600  # 20 days

    # [B4] Remove an unconfirmed guard if this much time has passed since
    # it was sampled (param-spec: guard-lifetime-days, default 120 days -
    # confirmed).
    GUARD_LIFETIME = 120 * 24 * 3600  # 120 days

    # [B4] Remove a confirmed guard if this much time has passed since it
    # was confirmed (param-spec: guard-confirmed-min-lifetime-days,
    # default 60 days - confirmed).
    GUARD_CONFIRMED_MIN_LIFETIME = 60 * 24 * 3600  # 60 days

    # [B5] Path bias thresholds. Verified against the real
    # circpathbias.c source (several of our earlier guesses were wrong -
    # in particular the extreme/notice rates were swapped).
    PB_MIN_CIRCS = 150         # pb_mincircs default (confirmed)
    PB_EXTREME_RATE = 0.30     # pb_extremepct default (confirmed, 30%)
    PB_MIN_USE = 20            # pb_minuse default (confirmed)
    PB_EXTREME_USE_RATE = 0.60 # pb_extremeusepct default (confirmed, 60%)

    # Very important: real Tor's pb_dropguards default is 0 (off), so even
    # when path bias looks bad, Tor only logs a warning - it does NOT
    # actually disable/exclude the guard by default. circpathbias.c's own
    # file docstring states "This code is currently configured in a
    # warning-only mode". So for a default-configuration simulation, this
    # exclusion logic should essentially never fire - hence the default of
    # False here. (Only set this to True if you specifically want to
    # simulate a client with PathBiasDropGuards=1.)
    PB_DROPGUARDS = False


class GuardState(object):
    """Per-guard persistent state, corresponding to entry_guard_t in
    entrynodes.c."""

    __slots__ = [
        'fprint', 'sampled_on', 'sampled_idx',
        'listed', 'unlisted_since',
        'confirmed_on', 'confirmed_idx',
        'unreachable_since', 'last_attempted',
        # [B5] path bias tracking (approximates guard_pathbias_t in
        # circpathbias.c)
        'circ_attempts', 'circ_successes',
        'use_attempts', 'use_successes',
        'path_bias_disabled',
    ]

    def __init__(self, fprint, sampled_on, sampled_idx):
        self.fprint = fprint
        self.sampled_on = sampled_on      # time first sampled
        self.sampled_idx = sampled_idx    # order sampled (for tie-breaks)
        self.listed = True                # currently present as a guard in the consensus?
        self.unlisted_since = None        # when did it stop being listed?
        self.confirmed_on = None          # when did we first successfully build a circuit through it?
        self.confirmed_idx = None         # order confirmed (used for primary-guard priority)
        self.unreachable_since = None     # when did it become unreachable?
        self.last_attempted = None        # time of last connection attempt
        # [B5] path bias: track separately whether a circuit was "built"
        # (circ) versus actually "used all the way through" (use, i.e. a
        # stream succeeded end-to-end)
        self.circ_attempts = 0
        self.circ_successes = 0
        self.use_attempts = 0
        self.use_successes = 0
        self.path_bias_disabled = False


class GuardSelectionState(object):
    """Manages the full guard state (SAMPLED/CONFIRMED/PRIMARY) for a single
    client."""

    def __init__(self):
        # fprint -> GuardState. Use OrderedDict to explicitly guarantee
        # insertion order (Python 2's plain dict does not guarantee order;
        # we do sort by sampled_idx anyway, but OrderedDict keeps iteration
        # stable too).
        self.sampled_guards = OrderedDict()
        self._next_sampled_idx = 0
        self._next_confirmed_idx = 0
        # PRIMARY_GUARDS is recomputed every time, but cached here for
        # callers to inspect.
        self.primary_guards = []
        # Cache of the weighted guard-candidate pool built by
        # add_new_sampled_guard(), reused across every guard addition and
        # every circuit within the same consensus period instead of
        # rebuilding it (a full weight/exit-policy pass over every relay)
        # on every single add. Keyed on id(cons_rel_stats) since a fresh
        # cons_rel_stats dict is only produced when a new network-state
        # period begins - mirrors how pathsim.py's legacy get_new_guard()
        # is fed a single weighted_guards pool computed once per period.
        self._weighted_pool = None
        self._weighted_pool_key = None
        # Memoizes update_listed_status()'s (cons_rel_stats, cur_time) key:
        # its result depends on nothing else, so a repeat call with the
        # same key (e.g. select_guard_for_circuit() being re-entered by
        # create_circuit()'s hibernating-guard retry loop, which reuses
        # the same circ_time) is a guaranteed no-op and can be skipped.
        self._last_listed_update_key = None

    # ---------- Managing SAMPLED_GUARDS ----------

    def update_listed_status(self, cons_rel_stats, cur_time):
        """Call on every consensus update. Updates listed status and
        removes stale guards. (Simplified version of
        entry_guards_update_all() -> sampled_guards_prune_obsolete_entries().
        Reflects all three removal conditions:
          1) unlisted for longer than REMOVE_UNLISTED_GUARDS_AFTER
          2) [B4] unconfirmed and sampled longer than GUARD_LIFETIME ago
          3) [B4] confirmed and confirmed longer than
             GUARD_CONFIRMED_MIN_LIFETIME ago
        """
        key = (id(cons_rel_stats), cur_time)
        if self._last_listed_update_key == key:
            return
        self._last_listed_update_key = key

        from stem import Flag  # same stem.Flag as used in pathsim.py

        to_remove = []
        for fprint, gs in self.sampled_guards.items():
            currently_listed = (
                fprint in cons_rel_stats and
                Flag.GUARD in cons_rel_stats[fprint].flags and
                Flag.RUNNING in cons_rel_stats[fprint].flags and
                Flag.V2DIR in cons_rel_stats[fprint].flags
            )
            if currently_listed:
                gs.listed = True
                gs.unlisted_since = None
            else:
                if gs.listed:
                    gs.listed = False
                    gs.unlisted_since = cur_time
                elif (gs.unlisted_since is not None) and \
                        (cur_time - gs.unlisted_since >=
                         GuardSelectionOptions.REMOVE_UNLISTED_GUARDS_AFTER):
                    to_remove.append(fprint)
                    continue

            # [B4] condition 2: unconfirmed guard sampled too long ago
            if (gs.confirmed_on is None) and \
                    (cur_time - gs.sampled_on >=
                     GuardSelectionOptions.GUARD_LIFETIME):
                to_remove.append(fprint)
                continue

            # [B4] condition 3: confirmed guard confirmed too long ago
            if (gs.confirmed_on is not None) and \
                    (cur_time - gs.confirmed_on >=
                     GuardSelectionOptions.GUARD_CONFIRMED_MIN_LIFETIME):
                to_remove.append(fprint)
                continue

        for fprint in to_remove:
            logger.debug('Removing guard %s from sample (unlisted/lifetime '
                          'expired).', fprint)
            del self.sampled_guards[fprint]

    def add_new_sampled_guard(self, bw_weights, bwweightscale, cons_rel_stats,
                               descriptors, cur_time, weighted_candidates=None):
        """Add one new guard to the SAMPLED_GUARDS pool, chosen by weighted
        random selection. Uses the same filter/weight logic as pathsim.py's
        existing get_new_guard(), but the difference is this is for the
        *permanent sample pool*, not "for this particular circuit"."""
        import pathsim  # imported inside function to avoid circular import

        if weighted_candidates is None:
            # reuse the pool built for this consensus period if we have
            # one cached (see _weighted_pool comment in __init__) instead
            # of re-filtering/re-weighting every relay on every single
            # guard addition.
            if self._weighted_pool_key != id(cons_rel_stats):
                candidates = pathsim.filter_guards(cons_rel_stats, descriptors)
                if not candidates:
                    raise ValueError(
                        'No new guard candidates available to sample.')
                weights = pathsim.get_position_weights(
                    candidates, cons_rel_stats, 'g', bw_weights, bwweightscale)
                self._weighted_pool = pathsim.get_weighted_nodes(
                    candidates, weights)
                self._weighted_pool_key = id(cons_rel_stats)
            weighted_candidates = self._weighted_pool

        # The cached pool isn't pruned as guards get added (removing an
        # entry would require re-normalizing every cumulative weight after
        # it), so a pick can land on an already-sampled guard - retry
        # rather than clobbering its existing GuardState. Mirrors the
        # conflict-retry pattern in pathsim.py's get_new_guard().
        for _ in range(50):
            new_fprint = pathsim.select_weighted_node(weighted_candidates)
            if new_fprint not in self.sampled_guards:
                break
        else:
            raise ValueError('No new guard candidates available to sample.')

        gs = GuardState(new_fprint, cur_time, self._next_sampled_idx)
        self._next_sampled_idx += 1
        self.sampled_guards[new_fprint] = gs
        logger.debug('Added new sampled guard: %s', new_fprint)
        return gs

    # ---------- FILTERED_GUARDS ----------

    def get_filtered_guards(self, cons_rel_stats, descriptors, exit_node,
                             fast=None, stable=None, extra_exclude=None):
        """Filter SAMPLED_GUARDS down to the ones currently usable
        (listed, no family/subnet conflict with the exit, fast/stable
        requirements).
        extra_exclude: [B6] optional iterable of fingerprints to
        additionally exclude (family/subnet/identity), used for conflux
        to keep this leg's guard from overlapping with the other leg's
        guard (guard_create_conflux_restriction() in entrynodes.c)."""
        import pathsim

        filtered = []
        for fprint, gs in self.sampled_guards.items():
            if not gs.listed:
                continue
            if gs.path_bias_disabled:  # [B5]
                continue
            if fprint not in cons_rel_stats or fprint not in descriptors:
                continue
            rel_stat = cons_rel_stats[fprint]
            from stem import Flag
            if fast and (Flag.FAST not in rel_stat.flags):
                continue
            if stable and (Flag.STABLE not in rel_stat.flags):
                continue
            if exit_node is not None:
                if fprint == exit_node:
                    continue
                if pathsim.in_same_family(cons_rel_stats, descriptors, exit_node, fprint):
                    continue
                if pathsim.in_same_subnet(descriptors, exit_node, fprint):
                    continue
            if extra_exclude:
                conflict = False
                for other in extra_exclude:
                    if (fprint == other) or\
                        pathsim.in_same_family(cons_rel_stats, descriptors, fprint, other) or\
                        pathsim.in_same_subnet(descriptors, fprint, other):
                        conflict = True
                        break
                if conflict:
                    continue
            filtered.append(fprint)
        return filtered

    def get_max_sample_size(self, cons_rel_stats, descriptors,
                             weighted_guards=None):
        """[B3] Returns the maximum size SAMPLED_GUARDS is allowed to grow
        to, mirroring get_max_sample_size() in entrynodes.c: the smaller
        of (a) an absolute cap (MAX_SAMPLE_SIZE_ABSOLUTE) and (b) a
        percentage of the total number of eligible guards currently in
        the consensus (MAX_SAMPLE_THRESHOLD_PERCENT) - but never smaller
        than MIN_FILTERED_SAMPLE_SIZE.

        weighted_guards: optional pre-filtered/weighted candidate pool
        (e.g. pathsim.py's once-per-period 'weighted_guards') - if given,
        its length is reused as the eligible-guard count instead of
        re-running filter_guards() over the whole consensus."""
        import pathsim
        period_key = id(cons_rel_stats)
        if _n_eligible_cache[0] == period_key:
            n_eligible = _n_eligible_cache[1]
        elif weighted_guards is not None:
            n_eligible = len(weighted_guards)
            _n_eligible_cache[0] = period_key
            _n_eligible_cache[1] = n_eligible
        else:
            n_eligible = len(pathsim.filter_guards(cons_rel_stats, descriptors))
            _n_eligible_cache[0] = period_key
            _n_eligible_cache[1] = n_eligible
        max_by_pct = int(n_eligible * GuardSelectionOptions.MAX_SAMPLE_THRESHOLD_PERCENT)
        max_absolute = GuardSelectionOptions.MAX_SAMPLE_SIZE_ABSOLUTE
        max_sample = min(max_by_pct, max_absolute)
        if max_sample < GuardSelectionOptions.MIN_FILTERED_SAMPLE_SIZE:
            return GuardSelectionOptions.MIN_FILTERED_SAMPLE_SIZE
        return max_sample

    def ensure_enough_filtered(self, cons_rel_stats, descriptors, exit_node,
                                bw_weights, bwweightscale, cur_time,
                                fast=None, stable=None, extra_exclude=None,
                                weighted_guards=None):
        """If FILTERED_GUARDS is too small, expand SAMPLED_GUARDS and
        re-filter. (Approximation of guard-spec's sample-expansion logic.)
        [B3] Stops expanding once SAMPLED_GUARDS hits its size cap, even
        if FILTERED_GUARDS is still below MIN_FILTERED_SAMPLE_SIZE - this
        matches entrynodes.c's entry_guards_expand_sample(), which gives
        up once n_sampled >= max_sample rather than looping forever.

        weighted_guards: optional pre-filtered/weighted candidate pool,
        shared across every client for this consensus period (e.g.
        pathsim.py's 'weighted_guards', built once in create_circuits()).
        When given, sample expansion reuses it instead of each client's
        GuardSelectionState redoing its own full filter_guards()/
        get_position_weights() pass over the whole consensus."""
        filtered = self.get_filtered_guards(
            cons_rel_stats, descriptors, exit_node, fast, stable, extra_exclude)

        max_sample_size = self.get_max_sample_size(
            cons_rel_stats, descriptors, weighted_guards)

        attempts = 0
        while (len(filtered) < GuardSelectionOptions.MIN_FILTERED_SAMPLE_SIZE
               and len(self.sampled_guards) < max_sample_size
               and attempts < 50):
            try:
                self.add_new_sampled_guard(
                    bw_weights, bwweightscale, cons_rel_stats,
                    descriptors, cur_time, weighted_candidates=weighted_guards)
            except ValueError:
                # No more candidates to draw from (small network) -
                # proceed with what we have.
                break
            filtered = self.get_filtered_guards(
                cons_rel_stats, descriptors, exit_node, fast, stable, extra_exclude)
            attempts += 1

        return filtered

    # ---------- PRIMARY_GUARDS ----------

    def compute_primary_guards(self, filtered_guards):
        """PRIMARY_GUARDS = CONFIRMED guards first, then fill any remaining
        slots from FILTERED in sampled_idx order. (Simplified version of
        entry_guards_update_primary().)"""
        confirmed_in_filtered = [
            f for f in filtered_guards
            if self.sampled_guards[f].confirmed_idx is not None
        ]
        confirmed_in_filtered.sort(
            key=lambda f: self.sampled_guards[f].confirmed_idx)

        primary = list(confirmed_in_filtered[:GuardSelectionOptions.NUM_PRIMARY_GUARDS])

        if len(primary) < GuardSelectionOptions.NUM_PRIMARY_GUARDS:
            remaining = [f for f in filtered_guards if f not in primary]
            remaining.sort(key=lambda f: self.sampled_guards[f].sampled_idx)
            need = GuardSelectionOptions.NUM_PRIMARY_GUARDS - len(primary)
            primary.extend(remaining[:need])

        self.primary_guards = primary
        return primary

    # ---------- Guard selection for a circuit (main entry point) ----------

    def select_guard_for_circuit(self, cons_rel_stats, descriptors,
                                  bw_weights, bwweightscale, exit_node,
                                  cur_time, fast=None, stable=None,
                                  guard_is_time_to_retry=None,
                                  extra_exclude=None, weighted_guards=None):
        """Main function to be called from create_circuit().

        Reflects the select_entry_guard_for_circuit() chain in
        entrynodes.c:
          1) select_primary_guard_for_circuit(): walk PRIMARY from the
             front, collecting up to NUM_PRIMARY_GUARDS_TO_USE "reachable"
             candidates, then pick *uniformly at random* among them (NOT a
             deterministic order!).
          2) If none found above, fall back to the first reachable
             CONFIRMED-but-non-primary guard (deterministic, sample order).
          3) If still none, the first reachable guard among FILTERED
             (deterministic).

        extra_exclude: [B6] optional iterable of fingerprints to
        additionally exclude - used for conflux, to keep this leg's guard
        from overlapping (family/subnet/identity) with the other leg's
        guard (guard_create_conflux_restriction() in entrynodes.c).

        weighted_guards: optional pre-filtered/weighted candidate pool
        shared across clients for this consensus period - see
        ensure_enough_filtered(). Avoids a per-client, per-period full
        consensus scan when this client's sample needs to grow.

        Returns: fingerprint of the selected guard
        """
        self.update_listed_status(cons_rel_stats, cur_time)

        filtered = self.ensure_enough_filtered(
            cons_rel_stats, descriptors, exit_node,
            bw_weights, bwweightscale, cur_time, fast, stable, extra_exclude,
            weighted_guards)

        if not filtered:
            raise ValueError('No usable guards available for this circuit.')

        primary = self.compute_primary_guards(filtered)

        def _is_reachable(fprint):
            gs = self.sampled_guards[fprint]
            if gs.unreachable_since is None:
                return True
            if guard_is_time_to_retry is not None:
                guard_dict_like = {
                    'last_attempted': gs.last_attempted,
                    'unreachable_since': gs.unreachable_since,
                }
                return guard_is_time_to_retry(guard_dict_like, cur_time)
            return False

        # 1) PRIMARY: walk from the front, collecting only reachable ones,
        #    up to NUM_PRIMARY_GUARDS_TO_USE. Pick randomly among those.
        usable_primary = []
        for fprint in primary:
            if _is_reachable(fprint):
                usable_primary.append(fprint)
                if len(usable_primary) >= GuardSelectionOptions.NUM_PRIMARY_GUARDS_TO_USE:
                    break
        if usable_primary:
            return choice(usable_primary)

        # 2) First reachable guard among CONFIRMED (non-primary) - deterministic
        confirmed_non_primary = [
            f for f in filtered
            if (f not in primary) and
               (self.sampled_guards[f].confirmed_idx is not None)
        ]
        confirmed_non_primary.sort(
            key=lambda f: self.sampled_guards[f].confirmed_idx)
        for fprint in confirmed_non_primary:
            if _is_reachable(fprint):
                return fprint

        # 3) Remaining FILTERED guards - first reachable one, in sample order
        remaining = [
            f for f in filtered
            if (f not in primary) and (f not in confirmed_non_primary)
        ]
        remaining.sort(key=lambda f: self.sampled_guards[f].sampled_idx)
        for fprint in remaining:
            if _is_reachable(fprint):
                return fprint

        # 4) Still nothing - everything is unreachable. Real Tor would mark
        #    all guards maybe-reachable at this point and retry from the
        #    top (mark_all_guards_maybe_reachable). Here we simplify by
        #    just forcing a retry of the first primary guard.
        logger.debug('All guards unreachable per schedule; forcing retry '
                      'of first primary guard.')
        return primary[0]

    def mark_guard_result(self, fprint, cur_time, succeeded):
        """Record the outcome of a circuit-build attempt through this
        guard. Promotes to confirmed on success. Also updates the [B5]
        path-bias "circ" level (whether a circuit was actually built) at
        the same time - the fact that this function is being called at
        all already means "we attempted to build a circuit through this
        guard", so the two naturally line up."""
        gs = self.sampled_guards[fprint]
        gs.last_attempted = cur_time
        gs.circ_attempts += 1
        if succeeded:
            gs.circ_successes += 1
            gs.unreachable_since = None
            if gs.confirmed_on is None:
                gs.confirmed_on = cur_time
                gs.confirmed_idx = self._next_confirmed_idx
                self._next_confirmed_idx += 1
                logger.debug('Guard %s confirmed (idx %d).',
                              fprint, gs.confirmed_idx)
        else:
            if gs.unreachable_since is None:
                gs.unreachable_since = cur_time

        self._check_path_bias(gs)

    def record_stream_use(self, fprint, succeeded):
        """[B5] Records the "use" level of path bias (whether a circuit
        was actually used successfully end-to-end by a stream). Note: this
        method is not yet wired up to be called from pathsim.py's
        client_assign_stream()/circuit_supports_stream() - "a circuit was
        successfully built" and "that circuit was actually used
        successfully all the way through by a stream" are separate
        concepts, and tracking the latter requires a separate hook in
        client_assign_stream(). Right now only the scaffolding exists."""
        gs = self.sampled_guards.get(fprint)
        if gs is None:
            return
        gs.use_attempts += 1
        if succeeded:
            gs.use_successes += 1
        self._check_path_bias(gs)

    def _check_path_bias(self, gs):
        """[B5] Simplified version of circpathbias.c's
        pathbias_measure_close_rate() / pathbias_measure_use_rate().
        Verified against the real source. Because PB_DROPGUARDS=False by
        default (matching real Tor's default), this function does not
        exclude anything under default settings - it simply returns early.
        Only set GuardSelectionOptions.PB_DROPGUARDS to True if you
        specifically want to simulate a client with PathBiasDropGuards=1.

        Also note: real Tor excludes conflux circuits
        (CIRCUIT_PURPOSE_CONFLUX_*) from path-bias accounting entirely
        (to prevent a malicious exit from forcing reconnections and
        thereby framing the guard). If simulating conflux, the caller
        should consider either not calling mark_guard_result() at all for
        conflux circuits, or routing them through a separate path.
        """
        if not GuardSelectionOptions.PB_DROPGUARDS:
            return
        # Real source uses strict '>' comparison, not '>='
        if gs.circ_attempts > GuardSelectionOptions.PB_MIN_CIRCS:
            if (gs.circ_successes / float(gs.circ_attempts) <
                    GuardSelectionOptions.PB_EXTREME_RATE):
                if not gs.path_bias_disabled:
                    logger.debug(
                        'Guard %s disabled by path bias (circ %d/%d).',
                        gs.fprint, gs.circ_successes, gs.circ_attempts)
                gs.path_bias_disabled = True
        if gs.use_attempts > GuardSelectionOptions.PB_MIN_USE:
            if (gs.use_successes / float(gs.use_attempts) <
                    GuardSelectionOptions.PB_EXTREME_USE_RATE):
                if not gs.path_bias_disabled:
                    logger.debug(
                        'Guard %s disabled by path bias (use %d/%d).',
                        gs.fprint, gs.use_successes, gs.use_attempts)
                gs.path_bias_disabled = True