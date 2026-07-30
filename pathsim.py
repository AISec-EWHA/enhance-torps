import datetime
import os
import os.path
import socket
from stem import Flag
from stem.exit_policy import ExitPolicy
from random import random, randint, choice
import sys
import collections
import cPickle as pickle
import argparse
from models import *
import congestion_aware_pathsim
#import vcs_pathsim
import process_consensuses
import re
import network_modifiers
import event_callbacks
import guard_selection_271
import importlib
import logging

logger = logging.getLogger(__name__)
_testing = False#True


class TorOptions:
    """Stores parameters set by Tor."""
    # given by #define ROUTER_MAX_AGE (60*60*48) in or.h    
    router_max_age = 60*60*48    
    
    num_guards = 1
    min_num_guards = 1
    guard_expiration_min = 60*24*3600 # min time until guard removed from list
    guard_expiration_max = 90*24*3600 # max time until guard removed from list 
    default_bwweightscale = 10000   
    
    # max age of a dirty circuit to which new streams can be assigned
    # set by MaxCircuitDirtiness option in Tor (default: 10 min.)
    max_circuit_dirtiness = 10*60
    
    # max age of a clean circuit
    # set by CircuitIdleTimeout in Tor (default: 60 min.)
    circuit_idle_timeout = 60*60
    
    # max number of preemptive clean circuits
    # given with "#define MAX_UNUSED_OPEN_CIRCUITS 14" in Tor's circuituse.c
    max_unused_open_circuits = 14
    
    # long-lived ports (taken from path-spec.txt)
    # including 6523, which was added in 0.2.4.12-alpha
    long_lived_ports = [21, 22, 706, 1863, 5050, 5190, 5222, 5223, 6523, 6667,
        6697, 8300]
    # observed port creates a need active for a limited amount of time
    # given with "#define PREDICTED_CIRCS_RELEVANCE_TIME 60*60" in rephist.c
    # need expires after an hour
    port_need_lifetime = 60*60 

    # time a guard can stay down until it is removed from list    
    # set by #define ENTRY_GUARD_REMOVE_AFTER (30*24*60*60) in entrynodes.c
    guard_down_time = 30*24*60*60 # time guard can be down until is removed
    
    # needs that apply to all samples
    # min coverage given with "#define MIN_CIRCUITS_HANDLING_STREAM 2" in or.h
    port_need_cover_num = 2
    
    # number of times to attempt to find circuit with at least one NTor hop
    # from #define MAX_POPULATE_ATTEMPTS 32 in circuicbuild.c
    max_populate_attempts = 32

    # [B6] Conflux (Proposal 329) consensus parameters, confirmed against
    # the real conflux_params.c source.
    cfx_enabled = True                   # cfx_enabled, default 1
    cfx_num_legs_set = 2                 # cfx_num_legs_set, default 2
    cfx_max_prebuilt_set = 3             # cfx_max_prebuilt_set, default 3
    # cfx_low_exit_threshold: spec-documented default is 60% (6000/10000),
    # but a real live consensus we inspected (2026-05-28) had this
    # overridden to 50% (5000/10000) - use the observed live value here
    # since it reflects actual current network behavior rather than the
    # untouched spec default. Re-check against a current consensus if
    # simulating a different period.
    cfx_low_exit_threshold = 0.50
    # Maximum number of times to retry building a leg before giving up
    # (cfx_max_unlinked_leg_retry, default 3) - not used by our simplified
    # model, which just retries hibernating nodes like create_circuit()
    # already does; kept here for reference/future use.
    cfx_max_unlinked_leg_retry = 3

    
class NetworkState:
    """Contains Tor network state in a consensus period needed to run
    simulation."""
    
    def __init__(self, cons_valid_after, cons_fresh_until, cons_bw_weights,
        cons_bwweightscale, cons_rel_stats, hibernating_statuses, descriptors):
        self.cons_valid_after = cons_valid_after
        self.cons_fresh_until = cons_fresh_until
        self.cons_bw_weights = cons_bw_weights
        self.cons_bwweightscale = cons_bwweightscale
        self.cons_rel_stats = cons_rel_stats
        self.hibernating_statuses = hibernating_statuses
        self.descriptors = descriptors
    

class RouterStatusEntry:
    """
    Represents a relay entry in a consensus document.
    Slim version of stem.descriptor.router_status_entry.RouterStatusEntry.
    """
    def __init__(self, fingerprint, nickname, flags, bandwidth,
        guardfraction=None, family_ids=None, supports_conflux=False):
        self.fingerprint = fingerprint
        self.nickname = nickname
        self.flags = flags
        self.bandwidth = bandwidth
        # F in [0,1]: fraction of time this relay has had the Guard flag
        # recently (Proposal 236). None if the consensus 'w' line didn't
        # include a GuardFraction entry (i.e. no recent Guard flag change).
        self.guardfraction = guardfraction
        # List of family ID strings (Happy Families, Proposal 321), e.g.
        # ['ed25519:AAAA...']. Empty list if the relay has none. Populated
        # by process_consensuses.py from up to two sources, merged
        # together (see issue #12):
        #   (a) server descriptors' 'family-cert' entries - always
        #       available regardless of whether --microdescs_dir was
        #       given, since server descriptors are read unconditionally
        #       and get republished ~every 18h even when unchanged.
        #   (b) microdescriptors' 'family-ids' line - only available if
        #       --microdescs_dir was given, and even then only as well as
        #       that archive's date-range coverage allows (microdescs are
        #       content-addressed and only re-archived when their content
        #       changes, so this source alone can have real gaps - source
        #       (a) doesn't have this problem).
        self.family_ids = family_ids if family_ids is not None else []
        # [B6] True iff the relay advertises Relay=5 in the consensus 'pr'
        # line (conflux protocol support). Only relevant for exit
        # selection - conflux only needs to be negotiated with the last
        # hop, so guards/middles don't need this.
        self.supports_conflux = supports_conflux
    

class NetworkStatusDocument:
    """
    Represents a consensus document.
    Slim version of stem.descriptor.networkstatus.NetworkStatusDocument.
    """
    def __init__(self, valid_after, fresh_until, bandwidth_weights, \
        bwweightscale, relays):
        self.valid_after = valid_after
        self.fresh_until = fresh_until
        self.bandwidth_weights = bandwidth_weights
        self.bwweightscale = bwweightscale
        self.relays = relays


class ServerDescriptor:
    """
    Represents a server descriptor.
    Slim version of stem.descriptor.server_descriptor.ServerDescriptor combined
    with stem.descriptor.server_descriptor.RelayDescriptor.
    """
    def __init__(self, fingerprint, hibernating, nickname, family, address,
        exit_policy, ntor_onion_key, ipv6_address=None):
        self.fingerprint = fingerprint
        self.hibernating = hibernating
        self.nickname = nickname
        self.family = family
        self.address = address
        self.exit_policy = exit_policy
        self.ntor_onion_key = ntor_onion_key
        # IPv6 OR address as a string, or None if the relay has none.
        # Used for IPv6 /32 subnet-conflict checks (mirrors
        # router_addrs_in_same_network()'s AF_INET6 case in nodelist.c).
        self.ipv6_address = ipv6_address


    def __getstate__(self):
        """Used for headache-free pickling. Turns ExitPolicy into its string
        representation, rather than using the repeatedly problematic object."""

        state = dict()
        state['fingerprint'] = self.fingerprint
        state['hibernating'] = self.hibernating
        state['nickname'] = self.nickname
        state['family'] = self.family
        state['address'] = self.address
        state['exit_policy'] = str(self.exit_policy)
        state['ntor_onion_key'] = self.ntor_onion_key
        state['ipv6_address'] = self.ipv6_address
        
        return state


    def __setstate__(self, state):
        """Used for headache-free unpickling. Creates ExitPolicy from string
        representation."""

        self.fingerprint = state['fingerprint']
        self.hibernating = state['hibernating']
        self.nickname = state['nickname']
        self.family = state['family']
        self.address = state['address']
        self.exit_policy = ExitPolicy(*state['exit_policy'].split(', '))
        self.ntor_onion_key = state['ntor_onion_key']
        # .get() with a default so pickles created before this field existed
        # (i.e. network-state files generated before this patch) still load.
        self.ipv6_address = state.get('ipv6_address', None)
    

def timestamp(t):
    """Returns UNIX timestamp"""
    td = t - datetime.datetime(1970, 1, 1)
    ts = td.days*24*60*60 + td.seconds
    return ts


def pad_network_state_files(network_state_files):
    """Add hour-long gaps into files list where gaps exist in file times."""
    nsf_date = None
    network_state_files_padded = []
    for nsf in network_state_files:
        f_datenums = map(int, os.path.basename(nsf).split('-')[:-1])
        new_nsf_date = datetime.datetime(f_datenums[0], f_datenums[1], f_datenums[2], f_datenums[3], f_datenums[4], f_datenums[5])
        if (nsf_date != None):
            td = new_nsf_date - nsf_date
            if (int(td.total_seconds()) != 3600):
                if (int(td.total_seconds()) % 3600 != 0):
                    raise ValueError('Gap between {0} and {1} not some number of hours.'.format(nsf_date, new_nsf_date))
                if _testing:
                    print('Missing consensuses between {0} and {1}'.\
                        format(nsf_date, new_nsf_date))
                num_missing_hours = int(td.total_seconds()/3600) - 1
                for i in range(num_missing_hours):
                    network_state_files_padded.append(None)
                network_state_files_padded.append(nsf)
            else:
                network_state_files_padded.append(nsf)
        else:
            network_state_files_padded.append(nsf)
        nsf_date = new_nsf_date                                    
    return network_state_files_padded


# Real node_select.c's compute_weighted_bandwidths() uses "that category's
# own" V2Dir multiplier for each category (guard-only, guard+exit,
# exit-only, middle): guard+exit -> Wd/Wdb, guard-only -> Wg/Wgb (the
# without-guard side is middle: Wm/Wmb), exit-only -> We/Web,
# middle -> Wm/Wmb.
_CATEGORY_MAIN_KEYS = {
    # (is_guard, is_exit) -> (weight_key, dir_key)
    (True, True):  ('Wd', 'Wdb'),
    (True, False): ('Wg', 'Wgb'),
    (False, True): ('We', 'Web'),
    (False, False):('Wm', 'Wmb'),
}
# The "without guard flag" category used for guardfraction blending:
# guard+exit -> exit-only, guard-only -> middle. (exit-only/middle nodes
# already have is_guard=False, so guardfraction doesn't apply to them in
# the first place - the real source never uses weight_without_guard_flag
# in that case either.)
_WITHOUT_GUARD_CATEGORY = {
    (True, True):  (False, True),   # guard+exit -> exit-only
    (True, False): (False, False),  # guard-only -> middle
}


def _position_weight_names(position):
    """For a given position ('g'/'m'/'e'), returns the consensus
    bandwidth-weights key name that each category (Wg/Wm/We/Wd) should
    actually reference. (Identical to the WEIGHT_FOR_GUARD/MID/EXIT
    branches in node_select.c.)"""
    if position == 'g':
        return {'Wg': 'Wgg', 'Wm': 'Wgm', 'We': None, 'Wd': 'Wgd'}
    elif position == 'm':
        return {'Wg': 'Wmg', 'Wm': 'Wmm', 'We': 'Wme', 'Wd': 'Wmd'}
    elif position == 'e':
        return {'Wg': 'Weg', 'Wm': 'Wem', 'We': 'Wee', 'Wd': 'Wed'}
    else:
        raise ValueError('get_bw_weight does not support position {0}.'.format(
            position))


def get_bw_weight(flags, position, bw_weights, bwweightscale=None,
    guardfraction=None):
    """Returns weight to apply to relay's bandwidth for given position.
    Mirrors node_select.c's compute_weighted_bandwidths() exactly:
      - BadExit relays are treated as not-exit for weighting (is_exit =
        Exit flag present AND NOT BadExit).
      - V2Dir relays get their weight multiplied by the matching
        category's Wgb/Wmb/Web/Wdb directory-cache weight; each of the
        "with guard flag" and "without guard flag" quantities used for
        guardfraction blending gets *its own* category's dir multiplier
        (this differs from a naive implementation that discounts only
        once, after blending).
      - guardfraction blending only applies when position != 'g' and the
        relay currently has the Guard flag (has_guardfraction), per
        Tor's `rule != WEIGHT_FOR_GUARD` condition.

        flags: list of Flag values for relay from a consensus
        position: 'g' (guard), 'm' (middle), or 'e' (exit)
        bw_weights: bandwidth_weights from NetworkStatusDocumentV3 consensus
        bwweightscale: consensus bwweightscale; if None, weights are used
             unnormalized (fine as long as this is applied consistently
             across all candidates being compared, since it's a constant
             overall scale factor - but passing it is recommended).
        guardfraction: float in [0,1] or None (see RouterStatusEntry)
    """
    is_guard = (Flag.GUARD in flags)
    is_exit = (Flag.EXIT in flags) and (Flag.BADEXIT not in flags)
    is_dir = (Flag.V2DIR in flags)

    names = _position_weight_names(position)
    scale = float(bwweightscale) if bwweightscale is not None else 1.0

    def _weight_for(cat_is_guard, cat_is_exit):
        cat_key, dir_key = _CATEGORY_MAIN_KEYS[(cat_is_guard, cat_is_exit)]
        weight_name = names[cat_key]
        if weight_name is None:
            # e.g. position=='g' has no 'We' entry; shouldn't be reached
            # for a real candidate in that category at that position.
            raise ValueError(
                'No {0} weight defined for position {1}.'.format(
                    cat_key, position))
        w = float(bw_weights[weight_name]) / scale
        if is_dir:
            w *= float(bw_weights[dir_key]) / scale
        return w

    weight = _weight_for(is_guard, is_exit)

    if (position != 'g') and is_guard and (guardfraction is not None):
        wg_cat = _WITHOUT_GUARD_CATEGORY[(is_guard, is_exit)]
        weight_without_guard = _weight_for(*wg_cat)
        weight = (guardfraction * weight +
                  (1.0 - guardfraction) * weight_without_guard)

    return weight

            
def select_weighted_node(weighted_nodes):
    """Takes (node,cum_weight) pairs where non-negative cum_weight increases,
    ending at 1. Use cum_weights as cumulative probablity to select a node."""
    r = random()
    begin = 0
    end = len(weighted_nodes)-1
    mid = int((end+begin)/2)
    while True:
        if (r <= weighted_nodes[mid][1]):
            if (mid == begin):
                return weighted_nodes[mid][0]
            else:
                end = mid
                mid = int((end+begin)/2)
        else:
            if (mid == end):
                raise ValueError('Weights must sum to 1.')
            else:
                begin = mid+1
                mid = int((end+begin)/2)


def might_exit_to_port(descriptor, port):
    """Returns if will exit to port for *some* ip.
    Is conservative - never returns a false negative."""
    for rule in descriptor.exit_policy:
        if (port >= rule.min_port) and\
                (port <= rule.max_port): # assumes full range for wildcard port
            if rule.is_accept:
                return True
            else:
                if (rule.is_address_wildcard()) or\
                    (rule.get_masked_bits() == 0):
                    return False
    return True # default accept if no rule matches


def can_exit_to_port(descriptor, port):
    """Derived from compare_unknown_tor_addr_to_addr_policy() in policies.c.
    That function returns ACCEPT, PROBABLY_ACCEPT, REJECT, and PROBABLY_REJECT.
    We ignore the PRABABLY status, as is done by Tor in the uses of
    compare_unknown_tor_addr_to_addr_policy() that we care about."""             
    for rule in descriptor.exit_policy:
        if (port >= rule.min_port) and\
                (port <= rule.max_port): # assumes full range for wildcard port
            if (rule.is_address_wildcard()) or\
                (rule.get_masked_bits() == 0):
                if rule.is_accept:
                    return True
                else:
                    return False
    return True # default accept if no rule matches
    
def policy_is_reject_star(exit_policy):
    """Replicates Tor function of same name in policies.c."""
    for rule in exit_policy:
        if rule.is_accept:
            return False
        elif (((rule.min_port <= 1) and (rule.max_port == 65535)) or\
                (rule.is_port_wildcard())) and\
            ((rule.is_address_wildcard()) or (rule.get_masked_bits == 0)):
            return True
    return True
        

def exit_filter(exit, cons_rel_stats, descriptors, fast, stable, internal, ip,\
    port, loose):
    """Applies the criteria for choosing a relay as an exit.
    If internal, doesn't consider exit policy.
    If IP and port given, simply applies exit policy.
    If just port given, guess as Tor does, with the option to be slightly more
    loose than Tor and avoid false negatives (via loose=True).
    If IP and port not given, check policy for any allowed exiting. This
    behavior is for SOCKS RESOLVE requests in particular."""
    rel_stat = cons_rel_stats[exit]
    desc = descriptors[exit]
    if (Flag.BADEXIT not in rel_stat.flags) and\
        (Flag.RUNNING in rel_stat.flags) and\
        (Flag.VALID in rel_stat.flags) and\
        ((not fast) or (Flag.FAST in rel_stat.flags)) and\
        ((not stable) or (Flag.STABLE in rel_stat.flags)):
        if (internal):
            # In an "internal" circuit final node is chosen just like a
            # middle node (ignoring its exit policy).
            return True
        elif (ip != None):
            return desc.exit_policy.can_exit_to(ip, port)
        elif (port != None):
            if (not loose):
                return can_exit_to_port(desc, port)
            else:
                return might_exit_to_port(desc, port)
        else:
            return (not policy_is_reject_star(desc.exit_policy))


def filter_exits(cons_rel_stats, descriptors, fast, stable, internal, ip,\
    port):
    """Applies exit filter to relays."""
    exits = []
    for fprint in cons_rel_stats:
        if exit_filter(fprint, cons_rel_stats, descriptors, fast, stable,\
            internal, ip, port, False):
            exits.append(fprint)
    return exits
    

def filter_exits_loose(cons_rel_stats, descriptors, fast, stable, internal,\
    ip, port):
    """Applies loose exit filter to relays."""    
    exits = []
    for fprint in cons_rel_stats:
        if exit_filter(fprint, cons_rel_stats, descriptors, fast, stable,\
            internal, ip, port, True):
            exits.append(fprint)
    return exits

    
def get_position_weights(nodes, cons_rel_stats, position, bw_weights,\
    bwweightscale):
    """Computes the consensus "bandwidth" weighted by position weights.
    get_bw_weight() already normalizes by bwweightscale internally, so we
    just multiply its (already-normalized) return value by raw bandwidth."""
    weights = {}
    for node in nodes:
        rel_stat = cons_rel_stats[node]
        bw = float(rel_stat.bandwidth)
        weight = get_bw_weight(rel_stat.flags, position, bw_weights,
            bwweightscale, getattr(rel_stat, 'guardfraction', None))
        weights[node] = bw * weight
    return weights 
    
                        
def get_weighted_nodes(nodes, weights):
    """Takes list of nodes (rel_stats) and weights (as a dict) and outputs
    a list of (node, cum_weight) pairs, where cum_weight is the cumulative
    probability of the nodes weighted by weights.
    """
    # compute total weight
    total_weight = 0
    for node in nodes:
        total_weight += weights[node]
    if (total_weight == 0):
        raise ValueError('ERROR: Node list has total weight zero.')
    # create cumulative weights
    weighted_nodes = []
    cum_weight = 0
    for node in nodes:
        cum_weight += weights[node]/total_weight
        weighted_nodes.append((node, cum_weight))
    
    return weighted_nodes         

    
def in_same_family(cons_rel_stats, descriptors, node1, node2):
    """Takes list of descriptors and two node fingerprints, and checks if
    they should be considered in the same family - true if EITHER:
      (a) they mutually list each other in their declared_family
          (the old MyFamily-based mechanism), OR
      (b) [#12] they share at least one common family ID (Happy Families,
          Proposal 321), per RouterStatusEntry.family_ids - sourced from
          server descriptors' family-cert entries and/or microdescriptors'
          family-ids line (see RouterStatusEntry.family_ids docstring).
    Mirrors nodes_in_same_family() checking both use_family_lists and
    use_family_ids conditions with an OR."""

    desc1 = descriptors[node1]
    desc2 = descriptors[node2]
    fprint1 = desc1.fingerprint
    fprint2 = desc2.fingerprint
    nick1 = desc1.nickname
    nick2 = desc2.nickname

    node1_lists_node2 = False
    for member in desc1.family:
        if ((member[0] == '$') and (member[1:] == fprint2)) or\
            (member == nick2):
            node1_lists_node2 = True

    if (node1_lists_node2):
        for member in desc2.family:
            if ((member[0] == '$') and (member[1:] == fprint1)) or\
                (member == nick1):
                return True

    # [#12] Family ID overlap check
    ids1 = getattr(cons_rel_stats.get(node1), 'family_ids', None) if node1 in cons_rel_stats else None
    ids2 = getattr(cons_rel_stats.get(node2), 'family_ids', None) if node2 in cons_rel_stats else None
    if ids1 and ids2 and (set(ids1) & set(ids2)):
        return True

    return False

    
def in_same_16_subnet(address1, address2):
    """Takes IPv4 addresses as strings and checks if the first two bytes
    are equal."""
    # check first octet
    i = 0
    while (address1[i] != '.'):
        if (address1[i] != address2[i]):
            return False
        i += 1
        
    i += 1
    while (address1[i] != '.'):
        if (address1[i] != address2[i]):
            return False
        i += 1
        
    return True


def in_same_ipv6_subnet(address1, address2):
    """Takes IPv6 addresses as strings and checks if the first 32 bits
    (first two 16-bit groups) match. Mirrors the AF_INET6 case of
    router_addrs_in_same_network() in nodelist.c, which uses a /32 mask
    (as opposed to /16 for IPv4). Returns False if either address is
    missing/malformed rather than raising."""
    if (not address1) or (not address2):
        return False
    try:
        b1 = socket.inet_pton(socket.AF_INET6, address1)
        b2 = socket.inet_pton(socket.AF_INET6, address2)
    except (socket.error, OSError, ValueError):
        return False
    return b1[:4] == b2[:4]


def in_same_subnet(descriptors, node1, node2):
    """Returns True if node1 and node2 should be considered in the same
    subnet for path-selection exclusion purposes - true if EITHER their
    IPv4 addresses share a /16, OR (if both have one) their IPv6 addresses
    share a /32. Mirrors nodes_in_same_family()/router_addrs_in_same_network()
    checking both address families and OR-ing the result, rather than only
    ever checking IPv4 (the previous pathsim.py behavior, issue #13)."""
    desc1 = descriptors[node1]
    desc2 = descriptors[node2]

    if in_same_16_subnet(desc1.address, desc2.address):
        return True

    ipv6_1 = getattr(desc1, 'ipv6_address', None)
    ipv6_2 = getattr(desc2, 'ipv6_address', None)
    if ipv6_1 and ipv6_2 and in_same_ipv6_subnet(ipv6_1, ipv6_2):
        return True

    return False


def middle_filter(node, cons_rel_stats, descriptors, fast=None,\
    stable=None, exit_node=None, guard_node=None, extra_exclude=None):
    """Return if candidate node is suitable as middle node. If an optional
    argument is omitted, then the corresponding filter condition will be
    skipped. This is useful for early filtering when some arguments are still
    unknown.
    extra_exclude: [B6] optional iterable of fingerprints to additionally
    exclude (family/subnet/identity), used for conflux to keep a leg's
    middle from overlapping with the other leg's guard/middle
    (conflux_add_middles_to_exclude_list() in circuitbuild.c)."""
    # Note that we intentionally allow non-Valid routers for middle
    # as per path-spec.txt default config    
    rel_stat = cons_rel_stats[node]
    if not ((Flag.RUNNING in rel_stat.flags) and\
            ((fast==None) or (not fast) or\
                (Flag.FAST in rel_stat.flags)) and\
            ((stable==None) or (not stable) or\
                (Flag.STABLE in rel_stat.flags)) and\
            ((exit_node==None) or\
                ((exit_node != node) and\
                    (not in_same_family(cons_rel_stats, descriptors, exit_node, node)) and\
                    (not in_same_subnet(descriptors, exit_node, node)))) and\
            ((guard_node==None) or\
                ((guard_node != node) and\
                    (not in_same_family(cons_rel_stats, descriptors, guard_node, node)) and\
                    (not in_same_subnet(descriptors, guard_node, node))))):
        return False
    if extra_exclude:
        for other in extra_exclude:
            if (node == other) or\
                in_same_family(cons_rel_stats, descriptors, node, other) or\
                in_same_subnet(descriptors, node, other):
                return False
    return True
                        

def select_middle_node(bw_weights, bwweightscale, cons_rel_stats, descriptors,\
    fast, stable, exit_node, guard_node, weighted_middles=None,
    extra_exclude=None):
    """Chooses a valid middle node by selecting randomly until one is found.
    extra_exclude: see middle_filter()."""

    # create weighted middles if not given
    if (weighted_middles == None):
        middles = cons_rel_stats.keys()
        # create cumulative weighted middles
        weights = get_position_weights(middles, cons_rel_stats, 'm',\
            bw_weights, bwweightscale)
        weighted_middles = get_weighted_nodes(middles, weights)    
    
    # select randomly until acceptable middle node is found
    i = 1
    while True:
        middle_node = select_weighted_node(weighted_middles)
        if _testing:
            print('select_middle_node() made choice #{0}.'.format(i))
        i += 1
        if (middle_filter(middle_node, cons_rel_stats, descriptors, fast,\
            stable, exit_node, guard_node, extra_exclude)):
            break
    return middle_node


def guard_is_time_to_retry(guard, time):
    """Tests if enough time has passed to retry an unreachable
    (i.e. hibernating) guard. Derived from entry_is_time_to_retry() in 
    entrynodes.c."""
    
    if (guard['last_attempted'] < guard['unreachable_since']):
        return True
    
    diff = time - guard['unreachable_since']
    if (diff < 6*60*60):
        return (time > (guard['last_attempted'] + 60*60))
    elif (diff < 3*24*60*60):
        return (time > (guard['last_attempted'] + 4*60*60))
    elif (diff < 7*24*60*60):
        return (time > (guard['last_attempted'] + 18*60*60))
    else:
        return (time > (guard['last_attempted'] + 36*60*60));


def guard_filter_for_circ(guard, cons_rel_stats, descriptors, fast,\
    stable, exit, circ_time, guards):
    """Returns if guard is usable for circuit."""
    #  - liveness (given by entry_is_live() call in choose_random_entry_impl())
    #       - not bad_since
    #       - has descriptor (although should be ensured by create_circuits()
    #       - not unreachable_since
    #  - fast/stable
    #  - not same as exit
    #  - not in exit family
    #  - not in exit /16
    # note that Valid flag not checked
    # note that hibernate status not checked (only checks unreachable_since)
    
    if (guards[guard]['bad_since'] == None):
        if (guard in cons_rel_stats) and (guard in descriptors):
            rel_stat = cons_rel_stats[guard]
            return ((not fast) or (Flag.FAST in rel_stat.flags)) and\
                ((not stable) or (Flag.STABLE in rel_stat.flags)) and\
                ((guards[guard]['unreachable_since'] == None) or\
                    guard_is_time_to_retry(guards[guard],circ_time)) and\
                (exit != guard) and\
                (not in_same_family(cons_rel_stats, descriptors, exit, guard)) and\
                (not in_same_subnet(descriptors, exit, guard))
        else:
            raise ValueError('Guard {0} not present in consensus or\ descriptors but wasn\'t marked bad.'.format(guard))
    else:
        return False


def filter_guards(cons_rel_stats, descriptors):
    """Returns relays filtered by general (non-client-specific) guard criteria.
    In particular, omits checks for IP/family/subnet conflicts within list.

    Mirrors node_is_possible_guard() in entrynodes.c, which requires
    node_is_dir(node) (i.e. the V2Dir flag) as part of guard eligibility -
    not just an optional weighting bonus, but a hard filter on the
    candidate pool itself.
    """
    guards = []
    for fprint in cons_rel_stats:
        rel_stat = cons_rel_stats[fprint]
        if (Flag.RUNNING in rel_stat.flags) and\
            (Flag.VALID in rel_stat.flags) and\
            (Flag.GUARD in rel_stat.flags) and\
            (Flag.V2DIR in rel_stat.flags) and\
            (fprint in descriptors):
            guards.append(fprint)   
    
    return guards
    

def get_new_guard(bw_weights, bwweightscale, cons_rel_stats, descriptors,\
    client_guards, weighted_guards=None):
    """Selects a new guard that doesn't conflict with the existing list."""
    # - doesn't conflict with current guards
    # - running
    # - valid
    # - need guard    
    # - need descriptor, though should be ensured already by create_circuits()
    # - not single hop relay
    # follows add_an_entry_guard(NULL,0,0,for_directory) call which appears
    # in pick_entry_guards() and more directly in choose_random_entry_impl()
    if (weighted_guards == None):
        # create weighted guards
        guards = filter_guards(cons_rel_stats, descriptors)
        guard_weights = get_position_weights(guards, cons_rel_stats,\
            'g', bw_weights, bwweightscale)
        weighted_guards = get_weighted_nodes(guards, guard_weights)    
               
    # Because conflict with current guards is unlikely,
    # randomly select a guard, test, and repeat if necessary
    i = 1
    while True:
        guard_node = select_weighted_node(weighted_guards)
        if _testing:
            print('get_new_guard() made choice #{0}.'.format(i))
        i += 1

        guard_conflict = False
        for client_guard in client_guards:
            if (client_guard == guard_node) or\
                (in_same_family(cons_rel_stats, descriptors, client_guard, guard_node)) or\
                (in_same_subnet(descriptors, client_guard, guard_node)):
                guard_conflict = True
                break
        if (not guard_conflict):
            break

    return guard_node

def get_guards_for_circ(bw_weights, bwweightscale, cons_rel_stats,\
    descriptors, fast, stable, guards,\
    exit,\
    circ_time, weighted_guards=None):
    """Obtains needed number of live guards that will work for circuit.
    Chooses new guards if needed, and *modifies* guard list by adding them."""
    # Get live guards then add new ones until TorOptions.num_guards reached,
    # where live is
    #  - bad_since isn't set
    #  - unreachable_since isn't set without retry
    #  - has descriptor, though create_circuits should ensure descriptor exists
    # Note that node need not have Valid flag to be live. As far as I can tell,
    # a Valid flag is needed to be added to the guard list, but isn't needed 
    # after that point.
    # Note that hibernating status is not an input here.
    # Rules derived from Tor source: choose_random_entry_impl() in entrynodes.c
    
    # add guards if not enough in list
    if (len(guards) < TorOptions.num_guards):
        # Oddly then only count the number of live ones
        # Slightly depart from Tor code by not considering the circuit's
        # fast or stable flags when finding live guards.
        # Tor uses fixed Stable=False and Fast=True flags when calculating # 
        # live but fixed Stable=Fast=False when adding guards here (weirdly).
        # (as in choose_random_entry_impl() and its pick_entry_guards() call)
        live_guards = filter(lambda x: (guards[x]['bad_since']==None) and\
                                (x in descriptors) and\
                                ((guards[x]['unreachable_since'] == None) or\
                                 guard_is_time_to_retry(guards[x],circ_time)),\
                            guards)
        for i in range(TorOptions.num_guards - len(live_guards)):
            new_guard = get_new_guard(bw_weights, bwweightscale,\
                cons_rel_stats, descriptors, guards,\
                weighted_guards)
            if _testing:                
                print('Need guard. Adding {0} [{1}]'.format(\
                    cons_rel_stats[new_guard].nickname, new_guard))
            expiration = randint(TorOptions.guard_expiration_min,\
                TorOptions.guard_expiration_max)
            guards[new_guard] = {'expires':(expiration+\
                circ_time), 'bad_since':None, 'unreachable_since':None,\
                'last_attempted':0, 'made_contact':False}

    # check for guards that will work for this circuit
    guards_for_circ = filter(lambda x: guard_filter_for_circ(x,\
        cons_rel_stats, descriptors, fast, stable, exit, circ_time, guards),\
        guards)
    # add new guards while there aren't enough for this circuit
    # adding is done without reference to the circuit - how Tor does it
    while (len(guards_for_circ) < TorOptions.min_num_guards):
            new_guard = get_new_guard(bw_weights, bwweightscale,\
                cons_rel_stats, descriptors, guards,\
                weighted_guards)
            if _testing:                
                print('Need guard for circuit. Adding {0} [{1}]'.format(\
                    cons_rel_stats[new_guard].nickname, new_guard))
            expiration = randint(TorOptions.guard_expiration_min,\
                TorOptions.guard_expiration_max)
            guards[new_guard] = {'expires':(expiration+\
                circ_time), 'bad_since':None, 'unreachable_since':None,\
                'last_attempted':0, 'made_contact':False}
            if (guard_filter_for_circ(new_guard, cons_rel_stats, descriptors,\
                fast, stable, exit, circ_time, guards)):
                guards_for_circ.append(new_guard)

    # return first TorOptions.num_guards usable guards
    return guards_for_circ[0:TorOptions.num_guards]


def circuit_covers_port_need(circuit, descriptors, port, need):
    """Returns if circuit satisfies a port need, ignoring the circuit
    time and need expiration."""
    return ((not need['fast']) or (circuit['fast'])) and\
            ((not need['stable']) or (circuit['stable'])) and\
            (can_exit_to_port(descriptors[circuit['path'][-1]], port))


def conflux_set_supports_stream(conflux_set, stream, descriptors):
    """[B6] Like circuit_supports_stream(), but for a conflux_set (which
    has 'exit_node' instead of a 'path' tuple, and is never internal -
    real Tor excludes onion-service/internal circuits from conflux
    entirely, per pathbias_should_count()'s CIRCUIT_PURPOSE_CONFLUX_*
    exclusions and conflux's general design)."""
    desc = descriptors[conflux_set['exit_node']]
    if (stream['type'] == 'connect'):
        if (stream['ip'] == None):
            raise ValueError('Stream must have ip.')
        if (stream['port'] == None):
            raise ValueError('Stream must have port.')
        return (desc.exit_policy.can_exit_to(stream['ip'], stream['port'])) and\
            ((conflux_set['stable']) or\
                (stream['port'] not in TorOptions.long_lived_ports))
    elif (stream['type'] == 'resolve'):
        return (not policy_is_reject_star(desc.exit_policy))
    else:
        raise ValueError('ERROR: Unrecognized stream in \
conflux_set_supports_stream: {0}'.format(stream['type']))


def circuit_supports_stream(circuit, stream, descriptors):
    """Returns if stream can run over circuit (which is assumed live)."""

    if (stream['type'] == 'connect'):
        if (stream['ip'] == None):
            raise ValueError('Stream must have ip.')
        if (stream['port'] == None):
            raise ValueError('Stream must have port.')
    
        desc = descriptors[circuit['path'][-1]]
        if (desc.exit_policy.can_exit_to(stream['ip'], stream['port'])) and\
            (not circuit['internal']) and\
            ((circuit['stable']) or\
                (stream['port'] not in TorOptions.long_lived_ports)):
            return True
        else:
            return False
    elif (stream['type'] == 'resolve'):
        desc = descriptors[circuit['path'][-1]]
        if (not policy_is_reject_star(desc.exit_policy)) and\
            (not circuit['internal']):
            return True
        else:
            return False
    else:
        raise ValueError('ERROR: Unrecognized stream in \
circuit_supports_stream: {0}'.format(stream['type']))

        
def uncover_circuit_ports(circuit, port_needs_covered):
    """Reduces cover count for ports that circuit indicates it covers."""
    for port in circuit['covering']:
        if (port in port_needs_covered):
            port_needs_covered[port] -= 1
            if _testing:                                                
                print('Decreased cover count for port {0} to {1}.'.\
format(port, port_needs_covered[port]))
        else:
            raise ValueError('Port {0} not found in port_needs_covered'.\
                format(port))
    
    
def kill_circuits_by_relay(client_state, relay_down_fn, msg):
    """Kill circuits with a relay that is down as judged by relay_down_fn."""    
    # go through dirty circuits
    new_dirty_exit_circuits = collections.deque()
    while(len(client_state['dirty_exit_circuits']) > 0):
        circuit = client_state['dirty_exit_circuits'].popleft()
        rel_down = None
        for i in range(len(circuit['path'])):
            relay = circuit['path'][i]
            if relay_down_fn(relay):
                rel_down = relay
                break
        if (rel_down == None):
            new_dirty_exit_circuits.append(circuit)
        else:
            if (_testing):
                print('Killing dirty circuit because {0} {1}.'.\
                    format(rel_down, msg))
    client_state['dirty_exit_circuits'] = new_dirty_exit_circuits
    # go through clean circuits
    new_clean_exit_circuits = collections.deque()
    while(len(client_state['clean_exit_circuits']) > 0):
        circuit = client_state['clean_exit_circuits'].popleft()
        rel_down = None
        for i in range(len(circuit['path'])):
            relay = circuit['path'][i]
            if relay_down_fn(relay):
                rel_down = relay
                break
        if (rel_down == None):
            new_clean_exit_circuits.append(circuit)
        else:
            if (_testing):
                print('Killing clean circuit because {0} {1}.'.\
                    format(rel_down, msg))
            uncover_circuit_ports(circuit, client_state['port_needs_covered'])
    client_state['clean_exit_circuits'] = new_clean_exit_circuits

    # [B6] go through dirty conflux sets - a set is killed if the shared
    # exit or *any* leg's guard/middle is down (simplification: real Tor
    # can potentially keep a set alive on its remaining leg if only one
    # leg's node fails, but modeling partial-set survival is out of scope
    # here).
    def _conflux_set_down(conflux_set):
        if relay_down_fn(conflux_set['exit_node']):
            return conflux_set['exit_node']
        for (guard_node, middle_node) in conflux_set['legs']:
            if relay_down_fn(guard_node):
                return guard_node
            if relay_down_fn(middle_node):
                return middle_node
        return None

    new_dirty_conflux_sets = collections.deque()
    while (len(client_state['dirty_conflux_sets']) > 0):
        conflux_set = client_state['dirty_conflux_sets'].popleft()
        rel_down = _conflux_set_down(conflux_set)
        if (rel_down == None):
            new_dirty_conflux_sets.append(conflux_set)
        else:
            if (_testing):
                print('Killing dirty conflux set because {0} {1}.'.
                    format(rel_down, msg))
    client_state['dirty_conflux_sets'] = new_dirty_conflux_sets

    new_clean_conflux_sets = collections.deque()
    while (len(client_state['clean_conflux_sets']) > 0):
        conflux_set = client_state['clean_conflux_sets'].popleft()
        rel_down = _conflux_set_down(conflux_set)
        if (rel_down == None):
            new_clean_conflux_sets.append(conflux_set)
        else:
            if (_testing):
                print('Killing clean conflux set because {0} {1}.'.
                    format(rel_down, msg))
    client_state['clean_conflux_sets'] = new_clean_conflux_sets


def get_network_state(ns_file):
    """Reads in network state file, returns NetworkState object."""
    if _testing:
        print('Using file {0}'.format(ns_file))

    cons_rel_stats = {}
    with open(ns_file, 'r') as nsf:
        consensus = pickle.load(nsf)
        new_descriptors = pickle.load(nsf)
        hibernating_statuses = pickle.load(nsf)
        
    # set variables from consensus
    cons_valid_after = timestamp(consensus.valid_after)            
    cons_fresh_until = timestamp(consensus.fresh_until)
    cons_bw_weights = consensus.bandwidth_weights
    if (consensus.bwweightscale == None):
        cons_bwweightscale = TorOptions.default_bwweightscale
    else:
        cons_bwweightscale = consensus.bwweightscale
    for relay in consensus.relays:
        if (relay in new_descriptors):
            cons_rel_stats[relay] = consensus.relays[relay]
    
    return NetworkState(cons_valid_after, cons_fresh_until, cons_bw_weights,
        cons_bwweightscale, cons_rel_stats, hibernating_statuses,
        new_descriptors)


def get_network_states(network_state_files, network_modifiers):
    """Generator that yields NetworkState object produced from
    list of network state files and modifiers to apply.
    Input:
        network_state_files: list of filenames with sequential network statuses
            as produced by pad_network_state_files(), i.e. no time gaps except
            as indicated by None entries
        network_modifiers: (list) contains objects to modify to network state in
            order via modify_network_state() method
    Output:
        network_states: iterator yielding sequential NetworkState objects or
            None
    """

    for ns_file in network_state_files:
        if (ns_file is not None):
            # get network state variables from file    
            network_state = get_network_state(ns_file)
            # apply network modifications
            for network_modifier in network_modifiers:
                network_modifier.modify_network_state(network_state)
        else:
            network_state = None
        yield network_state        


def set_initial_hibernating_status(hibernating_status, hibernating_statuses,
    cur_period_start, cons_rel_stats):
    """Reads hibernating statuses and updates initial relay status."""
    while (hibernating_statuses) and\
        (hibernating_statuses[-1][0] <= cur_period_start):
        hs = hibernating_statuses.pop()
        if (hs[1] in hibernating_status) and _testing:
            print('Reset hibernating of {0}:{1} to {2}.'.format(\
                cons_rel_stats[hs[1]].nickname, hibernating_status[hs[1]],
                    hs[2]))
        hibernating_status[hs[1]] = hs[2]
        if _testing:
            if (hs[2]):
                print('{0} was hibernating at start of consensus period.'.\
                    format(cons_rel_stats[hs[1]].nickname))        
                                

def period_client_update(client_state, cons_rel_stats, cons_fresh_until,\
    cons_valid_after):
    """Updates client state for new consensus period."""
    if _testing:
        print('Updating state for client {0} given new consensus.'.\
            format(client_state['id']))
            
    # Update guard list (Proposal 271 version)
    # This used to directly manipulate the guards dict's bad_since/expires
    # fields here, but that logic has moved into
    # GuardSelectionState.update_listed_status() (listed/unlisted
    # determination + removing guards unlisted or expired for too long -
    # this now also covers the old logic's two conditions, "remove if past
    # guard_down_time" and "remove if past expires", which correspond to
    # guard-spec's REMOVE_UNLISTED_GUARDS_AFTER / GUARD_LIFETIME /
    # GUARD_CONFIRMED_MIN_LIFETIME; see issue B4 in the issue tracker doc).
    guards = client_state['guards']
    guards.update_listed_status(cons_rel_stats, cons_valid_after)
    
    # Kill circuits using relays that now appear to be "down", where
    #  down is not in consensus or without Running flag.            
    kill_circuits_by_relay(client_state, \
        lambda r: (r not in cons_rel_stats) or \
            (Flag.RUNNING not in cons_rel_stats[r].flags),\
            'is down')
            
            
def timed_updates(cur_time, port_needs_global, client_states,
    hibernating_statuses, hibernating_status, cons_rel_stats):
    """Perform timing-based updates that apply to all clients."""            
    # expire port needs
    for port, need in port_needs_global.items():
        if (need['expires'] != None) and\
            (need['expires'] <= cur_time):
            if _testing:
                print('Port need for {0} expiring.'.format(port))
            # remove need from global list
            del port_needs_global[port]
            # remove coverage number and per-circuit coverage from client state
            for client_state in client_states:
                del client_state['port_needs_covered'][port]
                for circuit in client_state['clean_exit_circuits']:
                    circuit['covering'].discard(port)
    # update hibernating status
    while (hibernating_statuses) and\
        (hibernating_statuses[-1][0] <= cur_time):
        hs = hibernating_statuses.pop()
        if _testing:
            if (hs[1] in cons_rel_stats):
                if hs[2]:
                    print('{0}:{1} started hibernating.'.\
                        format(cons_rel_stats[hs[1]].nickname, hs[1]))
                else:
                    print('{0}:{1} stopped hibernating.'.\
                        format(cons_rel_stats[hs[1]].nickname, hs[1]))
            
        hibernating_status[hs[1]] = hs[2]
            

def timed_client_updates(cur_time, client_state, port_needs_global,
    cons_rel_stats, cons_valid_after,
    cons_fresh_until, cons_bw_weights, cons_bwweightscale, descriptors,
    hibernating_status, port_need_weighted_exits, weighted_middles,
    weighted_guards, congmodel, pdelmodel, callbacks=None,
    exit_conflux_ratio=0.0, conflux_stats=None):
    """Performs updates to client state that occur on a time schedule."""
    
    guards = client_state['guards']
            
    # kill old dirty circuits
    while (len(client_state['dirty_exit_circuits'])>0) and\
            (client_state['dirty_exit_circuits'][-1]['dirty_time'] <=\
                cur_time - TorOptions.max_circuit_dirtiness):
        if _testing:
            print('Killed dirty exit circuit at time {0} w/ dirty time \
{1}'.format(cur_time, client_state['dirty_exit_circuits'][-1]['dirty_time']))
        client_state['dirty_exit_circuits'].pop()
        
    # kill old clean circuits
    while (len(client_state['clean_exit_circuits'])>0) and\
            (client_state['clean_exit_circuits'][-1]['time'] <=\
                cur_time - TorOptions.circuit_idle_timeout):
        if _testing:
            print('Killed clean exit circuit at time {0} w/ time \
{1}'.format(cur_time, client_state['clean_exit_circuits'][-1]['time']))
        uncover_circuit_ports(client_state['clean_exit_circuits'][-1],\
            client_state['port_needs_covered'])
        client_state['clean_exit_circuits'].pop()

    # [B6] kill old dirty/clean conflux sets, same lifetime rules as
    # ordinary circuits (real Tor's conflux sets follow the same general
    # circuit lifetime handling in circuituse.c)
    while (len(client_state['dirty_conflux_sets'])>0) and\
            (client_state['dirty_conflux_sets'][-1]['dirty_time'] <=\
                cur_time - TorOptions.max_circuit_dirtiness):
        if _testing:
            print('Killed dirty conflux set at time {0}'.format(cur_time))
        client_state['dirty_conflux_sets'].pop()

    while (len(client_state['clean_conflux_sets'])>0) and\
            (client_state['clean_conflux_sets'][-1]['time'] <=\
                cur_time - TorOptions.circuit_idle_timeout):
        if _testing:
            print('Killed clean conflux set at time {0}'.format(cur_time))
        client_state['clean_conflux_sets'].pop()
        
    # kill circuits with relays that have gone into hibernation
    kill_circuits_by_relay(client_state, \
        lambda r: hibernating_status[r], 'is hibernating')

    # [B6] refill the prebuilt conflux pool up to
    # get_max_prebuilt_conflux_sets(exit_conflux_ratio). Real Tor prebuilds
    # these speculatively (not tied to a specific port/stream need), so we
    # don't gate this on port_needs_global the way ordinary clean circuits
    # are - it just tries to keep the pool topped up.
    if TorOptions.cfx_enabled:
        max_prebuilt = get_max_prebuilt_conflux_sets(exit_conflux_ratio)
        while len(client_state['clean_conflux_sets']) < max_prebuilt:
            try:
                new_set = create_conflux_set(cons_rel_stats,
                    cons_valid_after, cons_fresh_until, cons_bw_weights,
                    cons_bwweightscale, descriptors, hibernating_status,
                    guards, cur_time, True, False, congmodel, pdelmodel,
                    callbacks, weighted_middles, weighted_guards)
            except ValueError:
                # Not enough distinct usable nodes right now (e.g. very
                # small/sparse network) - stop trying this round rather
                # than looping forever.
                break
            client_state['clean_conflux_sets'].appendleft(new_set)
            if conflux_stats is not None:
                conflux_stats['sets_created'] += 1
            if _testing:
                print('Created prebuilt conflux set at time {0}.'.format(
                    cur_time))
                  
    # cover uncovered ports while fewer than
    # TorOptions.max_unused_open_circuits clean
    for port, need in port_needs_global.items():
        if (client_state['port_needs_covered'][port] < need['cover_num']):
            # we need to make new circuits
            # note we choose circuits specifically to cover all port needs,
            #  while Tor makes one circuit (per sec) that covers *some* port
            #  (see circuit_predict_and_launch_new() in circuituse.c)
            if _testing:                                
                print('Creating {0} circuit(s) at time {1} to cover port \
{2}.'.format(need['cover_num']-client_state['port_needs_covered'][port],\
 cur_time, port))
            while (client_state['port_needs_covered'][port] <\
                    need['cover_num']) and\
                (len(client_state['clean_exit_circuits']) < \
                    TorOptions.max_unused_open_circuits):
                new_circ = create_circuit(cons_rel_stats,
                    cons_valid_after, cons_fresh_until,
                    cons_bw_weights, cons_bwweightscale,
                    descriptors, hibernating_status, guards, cur_time,
                    need['fast'], need['stable'], False, None, port,
                    congmodel, pdelmodel,
                    port_need_weighted_exits[port],
                    True, weighted_middles, weighted_guards, callbacks)
                client_state['clean_exit_circuits'].appendleft(new_circ)
                
                # cover this port and any others
                client_state['port_needs_covered'][port] += 1
                new_circ['covering'].add(port)
                for pt, nd in port_needs_global.items():
                    if (pt != port) and\
                        (circuit_covers_port_need(new_circ,
                            descriptors, pt, nd)):
                        client_state['port_needs_covered'][pt] += 1
                        new_circ['covering'].add(pt)
                        
                        
def stream_update_port_needs(stream, port_needs_global,
    port_need_weighted_exits, client_states,
    descriptors, cons_rel_stats, cons_bw_weights, cons_bwweightscale):
    """Updates port needs based on input stream.
    If new port, returns updated list of exits filtered for port."""
    if (stream['type'] == 'resolve'):
        # as in Tor, treat RESOLVE requests as port 80 for
        #  prediction (see rep_hist_note_used_resolve())
        port = 80
    else:
        port = stream['port']
    if (port in port_needs_global):
        if (port_needs_global[port]['expires'] != None) and\
            (port_needs_global[port]['expires'] <\
                stream['time'] + TorOptions.port_need_lifetime):
            port_needs_global[port]['expires'] =\
                stream['time'] + TorOptions.port_need_lifetime
        return None
    else:
        port_needs_global[port] = {
            'expires':(stream['time']+TorOptions.port_need_lifetime),
            'fast':True,
            'stable':(port in TorOptions.long_lived_ports),
            'cover_num':TorOptions.port_need_cover_num}
        # adjust cover counts for the new port need
        for client_state in client_states:
            client_state['port_needs_covered'][port] = 0
            for circuit in client_state['clean_exit_circuits']:
                if (circuit_covers_port_need(circuit,\
                        descriptors, port,\
                        port_needs_global[port])):
                    client_state['port_needs_covered'][port]\
                        += 1
                    circuit['covering'].add(port)
        # precompute exit list and weights for new port need - cached per
        # (period, port, fast, stable), since this is identical no matter
        # which user's stream triggered it (see
        # _get_cached_port_need_exits())
        pn_weighted_exits = _get_cached_port_need_exits(
            cons_rel_stats, descriptors, cons_bw_weights, cons_bwweightscale,
            port_needs_global[port]['fast'], port_needs_global[port]['stable'],
            port)
        if _testing:
            print('# exits for new need at port {0}: {1}'.\
                format(port, len(pn_weighted_exits)))
        port_need_weighted_exits[port] = pn_weighted_exits
        
        
# Cache for get_stream_port_weighted_exits() / select_conflux_exit_node()
# / _get_cached_port_need_exits() / _period_pools_for(): the
# filtered+weighted candidate lists these build only depend on the
# current consensus (and, for exits, the (type, port) criteria) - not on
# which stream/circuit/user is asking - so every caller sharing the same
# period+criteria can reuse one computation instead of each re-scanning
# every relay from scratch. This lives at module level (not as a local in
# create_circuits()) because --user_model all calls create_circuits()
# once *per user* (thousands per chunk), each independently re-walking
# every network-state period in order; a per-call local cache would be
# rebuilt from zero on every single one of those calls.
#
# Keyed on id(cons_rel_stats), with one retained sub-dict per period
# (not just the single most-recent period): under --user_model all, the
# call order is user-major/period-minor - user 1 walks periods 1..N, then
# user 2 walks periods 1..N again, etc. - so a single-slot cache keyed on
# "most recent period" would be evicted by the time processing returns to
# period 1 for the next user and would *never* actually hit across users,
# defeating the point. Retaining one entry per period is safe here
# specifically because the same NetworkState objects (and hence the same
# cons_rel_stats instances) are held alive for the entire process via the
# materialized network_states_list in __main__, so id() can't be reused
# by an unrelated, later object; the cache is bounded by the number of
# distinct periods in the run (e.g. 24 for a one-day nsf_dir).
_exit_cache = {}


def _exit_cache_for_period(cons_rel_stats):
    period_key = id(cons_rel_stats)
    period_cache = _exit_cache.get(period_key)
    if period_cache is None:
        period_cache = {}
        _exit_cache[period_key] = period_cache
    return period_cache


def _get_cached_port_need_exits(cons_rel_stats, descriptors,
    cons_bw_weights, cons_bwweightscale, fast, stable, port):
    """Weighted exit list for a 'port need' (predictive circuit-building
    port), cached per (period, port, fast, stable). Used both by
    create_circuits()'s per-period port-need refresh and by
    stream_update_port_needs() when a stream introduces a new port need -
    both compute the exact same network-state-derived value for a given
    period/port, regardless of which user/client triggered it."""
    cache = _exit_cache_for_period(cons_rel_stats)
    cache_key = ('portneed', port, fast, stable)
    weighted_exits = cache.get(cache_key)
    if weighted_exits is None:
        port_need_exits = filter_exits(cons_rel_stats, descriptors, fast,
            stable, False, None, port)
        port_need_exit_weights = get_position_weights(port_need_exits,
            cons_rel_stats, 'e', cons_bw_weights, cons_bwweightscale)
        weighted_exits = get_weighted_nodes(port_need_exits,
            port_need_exit_weights)
        cache[cache_key] = weighted_exits
    return weighted_exits


# Cache for create_circuits()'s once-per-period pools: weighted_middles,
# weighted_guards, and exit_conflux_ratio all depend only on the current
# consensus, not on which user/client is being simulated. Same rationale
# and safety argument as _exit_cache above (--user_model all's
# once-per-user call pattern, cons_rel_stats objects kept alive for the
# whole run) - see the comment there.
_period_pool_cache = {}


def _period_pools_for(cons_rel_stats, descriptors, cons_bw_weights,
                       cons_bwweightscale):
    """Returns (weighted_middles, weighted_guards, exit_conflux_ratio) for
    this consensus period, computed once and reused by every
    create_circuits() call that processes the same period."""
    period_key = id(cons_rel_stats)
    pools = _period_pool_cache.get(period_key)
    if pools is None:
        potential_middles = filter(lambda x: middle_filter(x, cons_rel_stats,
            descriptors, None, None, None, None), cons_rel_stats.keys())
        potential_middle_weights = get_position_weights(potential_middles,
            cons_rel_stats, 'm', cons_bw_weights, cons_bwweightscale)
        weighted_middles = get_weighted_nodes(potential_middles,
            potential_middle_weights)

        potential_guards = filter_guards(cons_rel_stats, descriptors)
        potential_guard_weights = get_position_weights(potential_guards,
            cons_rel_stats, 'g', cons_bw_weights, cons_bwweightscale)
        weighted_guards = get_weighted_nodes(potential_guards,
            potential_guard_weights)

        exit_conflux_ratio = compute_exit_conflux_ratio(cons_rel_stats)

        pools = (weighted_middles, weighted_guards, exit_conflux_ratio)
        _period_pool_cache[period_key] = pools
    return pools


def get_stream_port_weighted_exits(stream_port, stream,
    cons_rel_stats, descriptors, cons_bw_weights, cons_bwweightscale):
    """Returns weighted exit list for port of stream."""
    cache = _exit_cache_for_period(cons_rel_stats)
    cache_key = ('stream', stream['type'], stream_port)
    if cache_key in cache:
        return cache[cache_key]

    if (stream['type'] == 'connect'):
        stable = (stream_port in TorOptions.long_lived_ports)
        stream_exits =\
            filter_exits_loose(cons_rel_stats,\
                descriptors, True, stable, False,\
                None, stream_port)
        if _testing:                        
            print('# loose exits for stream on port {0}: {1}'.\
                format(stream_port, len(stream_exits)))
    elif (stream['type'] == 'resolve'):
        stream_exits =\
            filter_exits(cons_rel_stats, descriptors, True,\
                False, False, None, None)                    
        if _testing:                        
            print('# exits for RESOLVE stream: {0}'.\
                format(len(stream_exits)))
    else:
        raise ValueError(\
            'ERROR: Unrecognized stream type: {0}'.\
            format(stream['type']))
    stream_exit_weights = get_position_weights(\
        stream_exits, cons_rel_stats, 'e',\
        cons_bw_weights, cons_bwweightscale)
    stream_weighted_exits = get_weighted_nodes(\
        stream_exits, stream_exit_weights)
    cache[cache_key] = stream_weighted_exits
    return stream_weighted_exits
        
        
def client_assign_stream(client_state, stream, cons_rel_stats,
    cons_valid_after, cons_fresh_until, cons_bw_weights, cons_bwweightscale,
    descriptors, hibernating_status, stream_weighted_exits,
    weighted_middles, weighted_guards, congmodel, pdelmodel, callbacks=None,
    conflux_stats=None):
    """Assigns a stream to a circuit for a given client.
    conflux_stats: [B6] optional dict with keys 'sets_used_for_stream' and
    'single_circuits_used_for_stream', incremented here so callers can
    report how much traffic actually ended up using conflux vs. plain
    single circuits (see the summary printed at the end of
    create_circuits())."""
        
    guards = client_state['guards']
    stream_assigned = None

    # try to use a dirty circuit
    for circuit in client_state['dirty_exit_circuits']:
        if (circuit['dirty_time'] > \
                stream['time'] - TorOptions.max_circuit_dirtiness) and\
            circuit_supports_stream(circuit, stream, descriptors):
            stream_assigned = circuit
            if _testing:                                
                if (stream['type'] == 'connect'):
                    print('Assigned CONNECT stream to port {0} to \
dirty circuit at {1}'.format(stream['port'], stream['time']))
                elif (stream['type'] == 'resolve'):
                    print('Assigned RESOLVE stream to dirty circuit \
at {0}'.format(stream['time']))
                else:
                    print('Assigned unrecognized stream to dirty circuit \
at {0}'.format(stream['time']))                                   
            break        
    # next try and use a clean circuit
    if (stream_assigned == None):
        new_clean_exit_circuits = collections.deque()
        while (len(client_state['clean_exit_circuits']) > 0):
            circuit = client_state['clean_exit_circuits'].popleft()
            if (circuit_supports_stream(circuit, stream, descriptors)):
                stream_assigned = circuit
                circuit['dirty_time'] = stream['time']
                client_state['dirty_exit_circuits'].appendleft(circuit)
                new_clean_exit_circuits.extend(\
                    client_state['clean_exit_circuits'])
                client_state['clean_exit_circuits'].clear()
                if _testing:
                    if (stream['type'] == 'connect'):
                        print('Assigned CONNECT stream to port {0} to \
clean circuit at {1}'.format(stream['port'], stream['time']))
                    elif (stream['type'] == 'resolve'):
                        print('Assigned RESOLVE stream to clean circuit \
at {0}'.format(stream['time']))
                    else:
                        print('Assigned unrecognized stream to clean circuit \
at {0}'.format(stream['time']))
                    
                # reduce cover count for covered port needs
                uncover_circuit_ports(circuit,\
                    client_state['port_needs_covered'])
            else:
                new_clean_exit_circuits.append(circuit)
        client_state['clean_exit_circuits'] =\
            new_clean_exit_circuits

    # [B6] next try to reuse a dirty conflux set
    if (stream_assigned == None) and TorOptions.cfx_enabled:
        for conflux_set in client_state['dirty_conflux_sets']:
            if (conflux_set['dirty_time'] > \
                    stream['time'] - TorOptions.max_circuit_dirtiness) and\
                conflux_set_supports_stream(conflux_set, stream, descriptors):
                stream_assigned = conflux_set
                if conflux_stats is not None:
                    conflux_stats['sets_used_for_stream'] += 1
                if _testing:
                    print('Assigned stream to dirty conflux set at {0}'.
                        format(stream['time']))
                break

    # [B6] next try to promote a clean (prebuilt) conflux set
    if (stream_assigned == None) and TorOptions.cfx_enabled:
        new_clean_conflux_sets = collections.deque()
        while (len(client_state['clean_conflux_sets']) > 0):
            conflux_set = client_state['clean_conflux_sets'].popleft()
            if (stream_assigned == None) and\
                conflux_set_supports_stream(conflux_set, stream, descriptors):
                stream_assigned = conflux_set
                conflux_set['dirty_time'] = stream['time']
                client_state['dirty_conflux_sets'].appendleft(conflux_set)
                if conflux_stats is not None:
                    conflux_stats['sets_used_for_stream'] += 1
                if _testing:
                    print('Assigned stream to clean (prebuilt) conflux '
                        'set at {0}'.format(stream['time']))
            else:
                new_clean_conflux_sets.append(conflux_set)
        client_state['clean_conflux_sets'] = new_clean_conflux_sets

    # if stream still unassigned we must make new circuit
    if (stream_assigned == None):
        if conflux_stats is not None:
            conflux_stats['single_circuits_used_for_stream'] += 1
        new_circ = None
        if (stream['type'] == 'connect'):
            stable = (stream['port'] in TorOptions.long_lived_ports)
            new_circ = create_circuit(cons_rel_stats,
                cons_valid_after, cons_fresh_until,
                cons_bw_weights, cons_bwweightscale,
                descriptors, hibernating_status, guards, stream['time'], True,
                stable, False, stream['ip'], stream['port'],
                congmodel, pdelmodel, stream_weighted_exits, False,
                weighted_middles, weighted_guards, callbacks)
        elif (stream['type'] == 'resolve'):
            new_circ = create_circuit(cons_rel_stats,
                cons_valid_after, cons_fresh_until,
                cons_bw_weights, cons_bwweightscale,
                descriptors, hibernating_status, guards, stream['time'], True,
                False, False, None, None, congmodel, pdelmodel,
                stream_weighted_exits, True,
                weighted_middles, weighted_guards, callbacks)
        else:
            raise ValueError('Unrecognized stream in client_assign_stream(): \
{0}'.format(stream['type']))        
        new_circ['dirty_time'] = stream['time']
        stream_assigned = new_circ
        client_state['dirty_exit_circuits'].appendleft(new_circ)
        if _testing: 
            if (stream['type'] == 'connect'):                           
                print('Created circuit at time {0} to cover CONNECT \
stream to ip {1} and port {2}.'.format(stream['time'], stream['ip'],\
stream['port'])) 
            elif (stream['type'] == 'resolve'):
                print('Created circuit at time {0} to cover RESOLVE \
stream.'.format(stream['time']))
            else: 
                print('Created circuit at time {0} to cover unrecognized \
stream.'.format(stream['time']))

    if (callbacks is not None):
        callbacks.stream_assignment(stream, stream_assigned)

    return stream_assigned

    
def select_exit_node(bw_weights, bwweightscale, cons_rel_stats, descriptors,\
    fast, stable, internal, ip, port, weighted_exits=None, exits_exact=False):
    """Chooses a valid exit node. To improve performance when simulating many
    streams, we allow any input weighted_exits list to possibly include
    relays that are invalid for the current circuit (thus we can create
    weighted_exits less often by only considering the port instead of the
    ip/port). Then we randomly select from that list until a suitable exit is
    found.
    """
    if (weighted_exits == None):    
        # filter exit list
        exits = filter_exits(cons_rel_stats, descriptors, fast,\
            stable, internal, ip, port)
        # create weights
        weights = None
        if (internal):
            weights = get_position_weights(exits, cons_rel_stats, 'm',\
                        bw_weights, bwweightscale)
        else:
            weights = get_position_weights(exits, cons_rel_stats, 'e',\
                bw_weights, bwweightscale)
        weighted_exits = get_weighted_nodes(exits, weights)      
        exits_exact = True
    
    if (exits_exact):
        return select_weighted_node(weighted_exits)
    else:
        # select randomly until acceptable exit node is found
        i = 1
        while True:
            exit_node = select_weighted_node(weighted_exits)
            if _testing:
                print('select_exit_node() made choice #{0}.'.format(i))
            i += 1
            if (exit_filter(exit_node, cons_rel_stats, descriptors, fast,\
                stable, internal, ip, port, False)):
                return exit_node    


def select_conflux_exit_node(bw_weights, bwweightscale, cons_rel_stats,
    descriptors, fast, stable, ip, port):
    """Like select_exit_node(), but restricted to exits that advertise
    conflux support (Relay=5). Conflux is only ever negotiated with the
    last hop, so this is the only place path selection needs to know
    about conflux support at all - guards and middles are picked exactly
    as they would be for an ordinary circuit."""
    cache = _exit_cache_for_period(cons_rel_stats)
    cache_key = ('conflux', fast, stable, ip, port)
    weighted_exits = cache.get(cache_key)
    if weighted_exits is None:
        exits = filter_exits(cons_rel_stats, descriptors, fast, stable, False,
            ip, port)
        exits = [e for e in exits if cons_rel_stats[e].supports_conflux]
        if not exits:
            raise ValueError('No conflux-supporting exits available.')
        weights = get_position_weights(exits, cons_rel_stats, 'e',
            bw_weights, bwweightscale)
        weighted_exits = get_weighted_nodes(exits, weights)
        cache[cache_key] = weighted_exits
    return select_weighted_node(weighted_exits)


def compute_exit_conflux_ratio(cons_rel_stats):
    """[B6] Fraction of Exit (non-BadExit) relays in the consensus that
    support conflux, mirroring count_exit_with_conflux_support() in
    conflux_params.c. Note this is a plain *count* ratio, not
    bandwidth-weighted, matching the real source exactly (`supported /
    total_exits`, no bandwidth involved)."""
    supported = 0
    total = 0
    for rel_stat in cons_rel_stats.values():
        if (Flag.EXIT not in rel_stat.flags) or (Flag.BADEXIT in rel_stat.flags):
            continue
        total += 1
        if rel_stat.supports_conflux:
            supported += 1
    if total == 0:
        return 0.0
    return float(supported) / float(total)


def get_max_prebuilt_conflux_sets(exit_conflux_ratio):
    """[B6] Returns how many conflux sets a client should keep prebuilt,
    mirroring conflux_params_get_max_prebuilt(): 0 if no exits support
    conflux at all, 1 if the supporting fraction is below
    cfx_low_exit_threshold, else cfx_max_prebuilt_set."""
    if exit_conflux_ratio <= 0.0:
        return 0
    if exit_conflux_ratio < TorOptions.cfx_low_exit_threshold:
        return 1
    return TorOptions.cfx_max_prebuilt_set


def circuit_supports_ntor(guard_node, middle_node, exit_node, descriptors):
    """Returns True if one node in circuit has ntor key."""
    
    for relay in (guard_node, middle_node, exit_node):
        if (descriptors[relay].ntor_onion_key is not None):
            return True
    return False

def create_circuit(cons_rel_stats, cons_valid_after, cons_fresh_until,
    cons_bw_weights, cons_bwweightscale, descriptors, hibernating_status,
    guards, circ_time, circ_fast, circ_stable, circ_internal, circ_ip,
    circ_port, congmodel, pdelmodel, weighted_exits=None,
    exits_exact=False, weighted_middles=None, weighted_guards=None,
    callbacks=None):
    """Creates path for requested circuit based on the input consensus
    statuses and descriptors.
    Inputs:
        cons_rel_stats: (dict) relay fingerprint keys and relay status vals
        cons_valid_after: (int) timestamp of valid_after for consensus
        cons_fresh_until: (int) timestamp of fresh_until for consensus
        cons_bw_weights: (dict) bw_weights of consensus
        cons_bwweightscale: (should be float()able) bwweightscale of consensus
        descriptors: (dict) relay fingerprint keys and descriptor vals
        hibernating_status: (dict) indicates hibernating relays
        guards: (dict) contains guards of requesting client
        circ_time: (int) timestamp of circuit request
        circ_fast: (bool) all relays should be fast
        circ_stable: (bool) all relays should be stable
        circ_internal: (bool) circuit is for name resolution or hidden service
        circ_ip: (str) IP address of destination (None if not known)
        circ_port: (int) desired TCP port (None if not known)
        congmodel: congestion model
        pdelmodel: propagation delay model
        weighted_exits: (list) (middle, cum_weight) pairs for exit position
        exits_exact: (bool) Is weighted_exits exact or does it need rechecking?
            weighed_exits is special because exits are chosen first and thus
            don't depend on the other circuit positions, and so potentially are        
            precomputed exactly.
        weighted_middles: (list) (middle, cum_weight) pairs for middle position
        weighted_guards: (list) (middle, cum_weight) pairs for middle position
        callbacks: object w/ method circuit_creation(circuit)
    Output:
        circuit: (dict) a newly created circuit with keys
            'time': (int) seconds from time zero
            'fast': (bool) relays must have Fast flag
            'stable': (bool) relays must have Stable flag
            'internal': (bool) is internal (e.g. for hidden service)
            'dirty_time': (int) timestamp of time dirtied, None if clean
            'path': (tuple) list in-order fingerprints for path's nodes
            'covering': (set) ports with needs covered by circuit        
    """
    
    if (circ_time < cons_valid_after) or\
        (circ_time >= cons_fresh_until):
        raise ValueError('consensus not fresh for circ_time in create_circuit')
 
    num_attempts = 0
    ntor_supported = False
    while (num_attempts < TorOptions.max_populate_attempts) and\
        (not ntor_supported):
        # select exit node
        i = 1
        while (True):
            exit_node = select_exit_node(cons_bw_weights, cons_bwweightscale,\
                cons_rel_stats, descriptors, circ_fast, circ_stable,\
                circ_internal, circ_ip, circ_port, weighted_exits, exits_exact)
    #        exit_node = select_weighted_node(weighted_exits)
            if (not hibernating_status[exit_node]):
                break
            if _testing:
                print('Exit selection #{0} is hibernating - retrying.'.\
                    format(i))
            i += 1
        if _testing:    
            print('Exit node: {0} [{1}]'.format(
                cons_rel_stats[exit_node].nickname,
                cons_rel_stats[exit_node].fingerprint))

        # select guard node (Proposal 271 version)
        # guards is now a GuardSelectionState instance. select_guard_for_circuit()
        # internally handles the SAMPLED->FILTERED->PRIMARY hierarchy,
        # "random choice among primaries" (B1), and "V2Dir required for
        # guard eligibility" (B2). Hibernating status is a different
        # concept from guard-spec's "unreachable" (temporary shutdown vs.
        # connection failure), but we simplify by treating it through the
        # same unreachable_since/mark_guard_result mechanism here.
        while True:
            guard_node = guards.select_guard_for_circuit(
                cons_rel_stats, descriptors, cons_bw_weights,
                cons_bwweightscale, exit_node, circ_time,
                circ_fast, circ_stable,
                guard_is_time_to_retry=guard_is_time_to_retry,
                weighted_guards=weighted_guards)
            if (hibernating_status[guard_node]):
                guards.mark_guard_result(guard_node, circ_time, False)
                if _testing:
                    print('[Time {0}]: Guard hibernating, retrying: {1}'.\
                        format(circ_time,
                            cons_rel_stats[guard_node].nickname))
            else:
                guards.mark_guard_result(guard_node, circ_time, True)
                break
        if _testing:
            print('Guard node: {0} [{1}]'.format(
                cons_rel_stats[guard_node].nickname,
                cons_rel_stats[guard_node].fingerprint))

        # select middle node
        # As with exit selection, hibernating status checked here to mirror Tor
        # selecting middle, having the circuit fail, reselecting a path,
        # and attempting circuit creation again.    
        i = 1
        while (True):
            middle_node = select_middle_node(cons_bw_weights,
                cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,
                circ_stable, exit_node, guard_node, weighted_middles)
            if (not hibernating_status[middle_node]):
                break
            if _testing:
                print('Middle selection #{0} is hibernating - retrying.'.\
                    format(i))
            i += 1    
        if _testing:
            print('Middle node: {0} [{1}]'.format(
                cons_rel_stats[middle_node].nickname,
                cons_rel_stats[middle_node].fingerprint))
                
        # ensure one member of the circuit supports the ntor handshake
        ntor_supported = circuit_supports_ntor(guard_node, middle_node,
            exit_node, descriptors)
        num_attempts += 1
    if _testing:
        if ntor_supported:
            print('Chose ntor-compatible circuit in {} tries'.\
                format(num_attempts))
    if (not ntor_supported):
        raise ValueError('ntor-compatible circuit not found in {} tries'.\
            format(num_attempts))

    circuit = {'time':circ_time,
            'fast':circ_fast,
            'stable':circ_stable,
            'internal':circ_internal,
            'dirty_time':None,
            'path':(guard_node, middle_node, exit_node),
            'covering':set()}

    # execute callback to allow logging on circuit creation
    if (callbacks is not None):
        callbacks.circuit_creation(circuit)

    return circuit


def create_conflux_set(cons_rel_stats, cons_valid_after, cons_fresh_until,
    cons_bw_weights, cons_bwweightscale, descriptors, hibernating_status,
    guards, circ_time, circ_fast, circ_stable, congmodel, pdelmodel,
    callbacks=None, weighted_middles=None, weighted_guards=None):
    """[B6] Creates a conflux set: TorOptions.cfx_num_legs_set (normally 2)
    circuit legs that share a single exit, with guards/middles picked
    independently per leg but excluded from overlapping (family/subnet/
    identity) with the other leg(s)' guard and middle. Mirrors the flow
    confirmed from the real source:
      - circuitbuild.c: onion_pick_cpath_exit() picks the exit *once*;
        both legs reuse it (never re-picked per leg).
      - entrynodes.c: guards_choose_guard() builds a
        guard_create_conflux_restriction() excluding the other leg's
        guard (and the exit) when choosing this leg's guard.
      - circuitbuild.c: build_middle_exclude_list() calls
        conflux_add_middles_to_exclude_list() to exclude other
        pending/built conflux legs' middles.

    Unlike create_circuit(), this does NOT implement the actual
    traffic-splitting/scheduling behavior between legs (MinRTT/LowRTT -
    see conflux.c) - it only reproduces path selection (which nodes end
    up in each leg). How traffic is actually divided between the two
    legs is left for a separate model (e.g. using pdelmodel) if you need
    to reason about per-leg observed traffic volume.

    Output: conflux_set (dict) with keys
        'time': (int) seconds from time zero
        'fast', 'stable': same meaning as in create_circuit()
        'exit_node': (str) fingerprint shared by all legs
        'legs': (list of tuples) each a (guard_node, middle_node) pair -
            combine with exit_node to get each leg's full path
        'dirty_time': None (set by caller when a leg/set starts being used)
    """
    if (circ_time < cons_valid_after) or\
        (circ_time >= cons_fresh_until):
        raise ValueError('consensus not fresh for circ_time in create_conflux_set')

    # Exit is chosen exactly once and shared by all legs.
    i = 1
    while True:
        exit_node = select_conflux_exit_node(cons_bw_weights,
            cons_bwweightscale, cons_rel_stats, descriptors, circ_fast,
            circ_stable, None, None)
        if not hibernating_status[exit_node]:
            break
        if _testing:
            print('Conflux exit selection #{0} is hibernating - retrying.'.
                format(i))
        i += 1
    if _testing:
        print('Conflux exit node: {0} [{1}]'.format(
            cons_rel_stats[exit_node].nickname,
            cons_rel_stats[exit_node].fingerprint))

    legs = []
    other_guards = []
    other_middles = []
    for leg_idx in range(TorOptions.cfx_num_legs_set):
        num_attempts = 0
        ntor_supported = False
        while (num_attempts < TorOptions.max_populate_attempts) and\
            (not ntor_supported):
            # guard for this leg - excluded from overlapping with other
            # legs' guards (guard_create_conflux_restriction)
            while True:
                guard_node = guards.select_guard_for_circuit(
                    cons_rel_stats, descriptors, cons_bw_weights,
                    cons_bwweightscale, exit_node, circ_time,
                    circ_fast, circ_stable,
                    guard_is_time_to_retry=guard_is_time_to_retry,
                    extra_exclude=other_guards,
                    weighted_guards=weighted_guards)
                if hibernating_status[guard_node]:
                    guards.mark_guard_result(guard_node, circ_time, False)
                    if _testing:
                        print('[Time {0}]: Conflux leg {1} guard '
                            'hibernating, retrying: {2}'.format(
                                circ_time, leg_idx,
                                cons_rel_stats[guard_node].nickname))
                else:
                    guards.mark_guard_result(guard_node, circ_time, True)
                    break

            # middle for this leg - excluded from overlapping with other
            # legs' guards AND middles (conflux_add_middles_to_exclude_list)
            middle_exclude = other_guards + other_middles
            j = 1
            while True:
                middle_node = select_middle_node(cons_bw_weights,
                    cons_bwweightscale, cons_rel_stats, descriptors,
                    circ_fast, circ_stable, exit_node, guard_node,
                    weighted_middles, extra_exclude=middle_exclude)
                if not hibernating_status[middle_node]:
                    break
                if _testing:
                    print('Conflux leg {0} middle selection #{1} is '
                        'hibernating - retrying.'.format(leg_idx, j))
                j += 1

            ntor_supported = circuit_supports_ntor(guard_node, middle_node,
                exit_node, descriptors)
            num_attempts += 1

        if not ntor_supported:
            raise ValueError('ntor-compatible conflux leg not found in '
                '{} tries'.format(num_attempts))

        if _testing:
            print('Conflux leg {0}: guard {1}, middle {2}'.format(
                leg_idx, cons_rel_stats[guard_node].nickname,
                cons_rel_stats[middle_node].nickname))

        legs.append((guard_node, middle_node))
        other_guards.append(guard_node)
        other_middles.append(middle_node)

    conflux_set = {'time': circ_time,
        'fast': circ_fast,
        'stable': circ_stable,
        'exit_node': exit_node,
        'legs': legs,
        'dirty_time': None,
        'covering': set()}

    if (callbacks is not None) and hasattr(callbacks, 'conflux_set_creation'):
        callbacks.conflux_set_creation(conflux_set)

    return conflux_set

def create_circuits(network_states, streams, num_samples, congmodel,
    pdelmodel, callbacks=None, shared_guards=False, client_id=None):
    """Takes streams over time and creates circuits by interaction
    with create_circuit().
      Input:
        network_states: iterator yielding NetworkState objects containing
            the sequence of simulation network states, with a None value
            indicating most recent status should be repeated with consensus
            valid/fresh times advanced 60 minutes
        streams: *ordered* list of streams, where a stream is a dict with keys
            'time': timestamp of when stream request occurs
            'type': 'connect' for SOCKS CONNECT, 'resolve' for SOCKS RESOLVE
            'ip': IP address of destination
            'port': desired TCP port
        num_samples: (int) # circuit-creation samples to take for given streams
        congmodel: (CongestionModel) outputs congestion used by some path algs
        pdelmodel: (PropagationDelayModel) outputs prop delay
        callbacks: obj providing callback interface, cf. event_callbacks module
        shared_guards: (bool) if True, all num_samples client states replaying
            these streams pull from a single shared GuardSelectionState
            (modeling num_samples concurrent circuits of one real client)
            instead of each sample getting its own independent guard list
            (modeling num_samples separate, unrelated clients).
        client_id: [client/dest] identifies which trace-file key/session
            these streams came from (e.g. the "circuit42_AS3320" key
            produced by trace_creator.py's --client-as option). Passed to
            callbacks.set_client_id() once, if the callbacks object
            defines that method (optional, for backwards compatibility
            with callback classes that don't - same pattern as the
            conflux_set_creation hasattr check below). None by default,
            matching the previous (no client identification) behavior.
    Output:
        Uses callbacks to produce any desired output.
    """
    if (callbacks is not None) and hasattr(callbacks, 'set_client_id'):
        callbacks.set_client_id(client_id)
    
    ### Simulation variables ###
    cur_period_start = None
    cur_period_end = None
    stream_start = 0
    stream_end = 0
    init = True

    # [B6] running totals for the conflux usage summary printed at the
    # end of this function.
    conflux_stats = {'sets_created': 0, 'sets_used_for_stream': 0,
        'single_circuits_used_for_stream': 0}

    # store old descriptors (for entry guards that leave consensus)
    # initialize with add_descriptors 
    descriptors = {}
    
    port_needs_global = {}

    # client states for each sample
    client_states = []
    # if shared_guards, all num_samples samples are concurrent circuits of
    # the *same* client and draw from one guard list; otherwise each sample
    # is an independent client with its own guard list
    common_guards = guard_selection_271.GuardSelectionState() if shared_guards\
        else None
    for i in range(num_samples):
        # guard is now not a plain dict but a GuardSelectionState instance
        # from guard_selection_271.py - holds the SAMPLED/FILTERED/PRIMARY
        # hierarchy and confirmed order (Proposal 271)
        # port_needs are ports that must be covered by existing circuits
        # circuit vars are ordered by increasing time since create or dirty
        port_needs_covered = {}
        client_states.append({'id':i,
                            'guards':(common_guards if shared_guards else\
                                guard_selection_271.GuardSelectionState()),
                            'port_needs_covered':port_needs_covered,
                            'clean_exit_circuits':collections.deque(),
                            'dirty_exit_circuits':collections.deque(),
                            'clean_conflux_sets':collections.deque(),
                            'dirty_conflux_sets':collections.deque()})
    ### End simulation variables ###
    
    # run simulation period one network state at a time
    for network_state in network_states:
        if (network_state != None):
            cons_valid_after = network_state.cons_valid_after
            cons_fresh_until = network_state.cons_fresh_until
            cons_bw_weights = network_state.cons_bw_weights
            cons_bwweightscale = network_state.cons_bwweightscale
            cons_rel_stats = network_state.cons_rel_stats
            hibernating_statuses = list(network_state.hibernating_statuses)
            new_descriptors = network_state.descriptors

            # clear hibernating status to ensure updates come from ns_file
            hibernating_status = {}
                        
            # update descriptors
            descriptors.update(new_descriptors)

        else:
            # gap in consensuses, just advance an hour, keeping network state            
            cons_valid_after += 3600
            cons_fresh_until += 3600
            # set empty statuses, even though previous should have been emptied
            hibernating_statuses = []            
            if _testing:
                print('Filling in consensus gap from {0} to {1}'.\
                format(cons_valid_after, cons_fresh_until))
                
        # update network state of callbacks object
        if (callbacks is not None):
            callbacks.set_network_state(cons_valid_after, cons_fresh_until,
                cons_bw_weights, cons_bwweightscale, cons_rel_stats,
                descriptors)        

        # update simulation period                
        if (cur_period_start == None):
            cur_period_start = cons_valid_after
        elif (cur_period_end == cons_valid_after):
            cur_period_start = cons_valid_after
        else:
            err = 'Gap/overlap in consensus times: {0}:{1}'.\
                    format(cur_period_end, cons_valid_after)
            raise ValueError(err)
        cur_period_end = cons_fresh_until  

        # set initial hibernating status
        set_initial_hibernating_status(hibernating_status,
            hibernating_statuses, cur_period_start, cons_rel_stats)
        
        if (init == True): # first period in simulation
            # seed port need
            port_needs_global[80] = \
                {'expires':(cur_period_start+TorOptions.port_need_lifetime),
                'fast':True, 'stable':False,
                'cover_num':TorOptions.port_need_cover_num}
            for client_state in client_states:
                client_state['port_needs_covered'][80] = 0
            init = False        
        
        # Update client state based on relay status changes in new consensus by
        # updating guard list and killing existing circuits.
        for client_state in client_states:
            period_client_update(client_state, cons_rel_stats,\
                cons_fresh_until, cons_valid_after)

        # filter exits for port needs and compute their weights - cached
        # per (period, port, fast, stable) since this is identical no
        # matter which user/client's create_circuits() call is asking
        # (see _get_cached_port_need_exits())
        port_need_weighted_exits = {}
        for port, need in port_needs_global.items():
            port_need_weighted_exits[port] = _get_cached_port_need_exits(
                cons_rel_stats, descriptors, cons_bw_weights,
                cons_bwweightscale, need['fast'], need['stable'], port)
            if _testing:
                print('# exits for port {0}: {1}'.\
                    format(port, len(port_need_weighted_exits[port])))

        # Store filtered exits for streams based only on port.
        # Conservative - never excludes a relay that exits to port for some ip.
        # Use port of None to store exits for resolve circuits.
        stream_port_weighted_exits = {}

        # filter/weight middles and guards, and compute exit_conflux_ratio
        # ([B6] fraction of Exit relays supporting conflux) - cached per
        # period (see _period_pools_for()), since none of these depend on
        # which user/client is being simulated, and --user_model all
        # re-enters this same per-period setup once per user (thousands
        # of times per chunk) without this cache.
        weighted_middles, weighted_guards, exit_conflux_ratio = \
            _period_pools_for(cons_rel_stats, descriptors, cons_bw_weights,
                cons_bwweightscale)
        if _testing:
            print('Exit conflux support ratio: {0:.3f} (max prebuilt: '
                '{1})'.format(exit_conflux_ratio,
                    get_max_prebuilt_conflux_sets(exit_conflux_ratio)))
       
        # for simplicity, step through time one minute at a time
        time_step = 60
        cur_time = cur_period_start
        while (cur_time < cur_period_end):
            # do updates that apply to all clients    
            timed_updates(cur_time, port_needs_global, client_states,
                hibernating_statuses, hibernating_status, cons_rel_stats)

            # do timed individual client updates
            for client_state in client_states:
                if (callbacks is not None):
                    callbacks.set_sample_id(client_state['id'])
                timed_client_updates(cur_time, client_state,
                    port_needs_global, cons_rel_stats,
                    cons_valid_after, cons_fresh_until, cons_bw_weights,
                    cons_bwweightscale, descriptors, hibernating_status,
                    port_need_weighted_exits, weighted_middles,
                    weighted_guards, congmodel, pdelmodel, callbacks,
                    exit_conflux_ratio, conflux_stats)
                    
            # collect streams that occur during current period
            while (stream_start < len(streams)) and\
                (streams[stream_start]['time'] < cur_time):
                stream_start += 1
            stream_end = stream_start
            while (stream_end < len(streams)) and\
                (streams[stream_end]['time'] < cur_time + time_step):
                stream_end += 1                                              
                
            # assign streams in this minute to circuits
            for stream_idx in range(stream_start, stream_end):
                stream = streams[stream_idx]
                
                # add need/extend expiration for ports in streams
                stream_update_port_needs(stream, port_needs_global,
                    port_need_weighted_exits, client_states, descriptors,
                    cons_rel_stats, cons_bw_weights, cons_bwweightscale)
                            
                # stream port for purposes of using precomputed exit lists
                if (stream['type'] == 'resolve'):
                    stream_port = None
                else:
                    stream_port = stream['port']
                # create weighted exits for this stream's port
                if (stream_port not in stream_port_weighted_exits):
                    stream_port_weighted_exits[stream_port] =\
                        get_stream_port_weighted_exits(stream_port, stream,
                        cons_rel_stats, descriptors,
                        cons_bw_weights, cons_bwweightscale)
                
                # do client stream assignment
                for client_state in client_states:
                    if (callbacks is not None):
                        callbacks.set_sample_id(client_state['id'])                
                    if _testing:                
                        print('Client {0} stream assignment.'.\
                            format(client_state['id']))
                    guards = client_state['guards']
                 
                    stream_assigned = client_assign_stream(\
                        client_state, stream, cons_rel_stats,
                        cons_valid_after, cons_fresh_until,
                        cons_bw_weights, cons_bwweightscale,
                        descriptors, hibernating_status,
                        stream_port_weighted_exits[stream_port],
                        weighted_middles, weighted_guards,
                        congmodel, pdelmodel, callbacks, conflux_stats)
            
            cur_time += time_step

    if TorOptions.cfx_enabled:
        total_streams = (conflux_stats['sets_used_for_stream'] +
            conflux_stats['single_circuits_used_for_stream'])
        pct_conflux = (100.0 * conflux_stats['sets_used_for_stream'] /
            total_streams) if total_streams else 0.0
        # Printed to stderr rather than stdout - stdout carries the
        # parseable per-circuit TSV output, and mixing this human-readable
        # summary into it breaks downstream parsing.
        print >> sys.stderr, ''
        print >> sys.stderr, '=== Conflux usage summary ==='
        print >> sys.stderr, 'Prebuilt conflux sets created: {0}'.format(
            conflux_stats['sets_created'])
        print >> sys.stderr, 'Streams assigned to a conflux set: {0}'.format(
            conflux_stats['sets_used_for_stream'])
        print >> sys.stderr, \
            'Streams assigned to an ordinary single circuit: {0}'.format(
            conflux_stats['single_circuits_used_for_stream'])
        print >> sys.stderr, 'Fraction of streams using conflux: {0:.1f}%'.format(
            pct_conflux)
        print >> sys.stderr, ('(Note: this reflects path-selection/pool '
            'availability only - actual per-leg traffic split, i.e. '
            'MinRTT/LowRTT scheduling, is not modeled here; see '
            'create_conflux_set() docstring.)')


def get_user_model(start_time, end_time, tracefilename=None,
    session='simple=600'):
    streams = []
    if (re.match('simple', session)):
        # simple user that makes a port 80 request every x seconds
        match = re.match('simple=([0-9]+)', session)
        if (match):
            http_request_wait = int(match.group(1))
        else:
            http_request_wait = 600
        str_ip = '74.125.131.105' # www.google.com
        for t in xrange(start_time, end_time, http_request_wait):
            streams.append({'time':t,'type':'connect','ip':str_ip,'port':80})
    elif (re.match('all',session)):
        ut = UserTraces.from_pickle(tracefilename)
        um = UserModel(ut, start_time, end_time)
        return {key: um.get_streams(key) for key in um.model.keys()}
    else:
        ut = UserTraces.from_pickle(tracefilename)
        um = UserModel(ut, start_time, end_time)
        streams = um.get_streams(session)
    return streams


if __name__ == '__main__':
    import argparse

    # parse arguments    
    parser = argparse.ArgumentParser(\
        description='Commands to run the Tor Path Simulator (TorPS)')

    subparsers = parser.add_subparsers(help='TorPS commands', dest='subparser')

    process_parser = subparsers.add_parser('process',
        help='Process Tor consensuses and descriptors. This matches relays in \
each consensus with the most-recently-seen descriptors. Also store changes in \
hibernation status that occur during the consensus period as revealed by \
multiple published descriptors. The consensus, matched descriptors, and \
hibernating statuses are pickled and written to disk.')
    process_parser.add_argument('--start_year', type=int,
        help='year in which to begin processing')
    process_parser.add_argument('--start_month', type=int,
        help='month in which to begin processing')
    process_parser.add_argument('--end_year', type=int,
        help='year in which to end processing')
    process_parser.add_argument('--end_month', type=int,
        help='month in which to end processing')
    process_parser.add_argument('--in_dir',
        help='directory in which input consensus and descriptor \
directories are located')
    process_parser.add_argument('--out_dir',
        help='directory in which to locate output network state files')
    process_parser.add_argument('--fat', action='store_true',
        help='Output the "fat" representation instead of TorPS classes, which TorPS cannot use for simulation')
    process_parser.add_argument('--initial_descriptor_dir', default=None,
        help='Directory containing descriptors to initialize consensus processing. Needed to provide first consensuses in a month with descriptors only contained in archive from previous month. If omitted, first 24 hours of network state files will likely omit relays due to missing descriptors.')
    process_parser.add_argument('--microdescs_dir', default=None,
        help='Optional. Path to a parent folder containing one or more '
             'extracted CollecTor "microdescs" archives (however nested - '
             'e.g. several months extracted side by side; the whole tree '
             'is searched recursively). Used as a supplementary source of '
             'family IDs (Happy Families / Proposal 321) for '
             'family-conflict checks, on top of the family-cert entries '
             'already read from server descriptors regardless of this '
             'setting (see RouterStatusEntry.family_ids in pathsim.py). '
             'Since microdescriptors are only re-published when their '
             'content changes, this source alone usually needs to cover a '
             'much wider date range than --in_dir/--out_dir to add much - '
             'check the family ID coverage summary printed at the end of '
             'this command. If omitted, family_ids still gets populated '
             'from server descriptors\' family-cert entries; you just '
             'lose whatever extra coverage the microdescriptor family-ids '
             'line would add on top.')


    simulate_parser = subparsers.add_parser('simulate',
        help='Do simulated path selections.')
    simulate_parser.add_argument('--nsf_dir', default='out/network-state-files',
        help='stores the network state files to use')
    simulate_parser.add_argument('--num_samples', type=int, default=1,
        help='number of simulations to execute')
    simulate_parser.add_argument('--shared_guards', action='store_true',
        help='if set, the num_samples circuit-building slots for a given '
             'client/stream share a single guard list (modeling num_samples '
             'concurrent circuits of one real client) instead of each '
             'getting its own independent guard list (the default, modeling '
             'num_samples separate, unrelated clients)')
    simulate_parser.add_argument('--trace_file', default="in/users2-processed.traces.pickle",
        help='name of files containing the user traces')
    simulate_parser.add_argument('--user_model', default='simple=600',
        help='user model to build out of traces, with standard trace file one \
of "facebook", "gmailgchat", "gcalgdocs", "websearch", "irc", "bittorrent", \
"typical", "best", "worst", "simple=[seconds/request]"')
    simulate_parser.add_argument('--output_class',
        default='event_callbacks.PrintStreamAssignments',
        help='class implementing callbacks on circuit and stream creation, e.g. for producing simulation output')
    simulate_parser.add_argument('--format', default='normal',
        help='argument sent to output_class, e.g. specifying the format of simulation output, choices for default PrintStreamAssignments class are "normal", "testing", "relay-adv", "network-adv"')
    simulate_parser.add_argument('--adv_guard_cons_bw', type=float, default=0,
        help='consensus bandwidth of each adversarial guard to add')
    simulate_parser.add_argument('--adv_exit_cons_bw', type=float, default=0,
        help='consensus bandwidth of each adversarial exit to add')
    simulate_parser.add_argument('--adv_time', type=int, default=0,
        help='indicates timestamp after which to add adversarial relays to \
consensuses')
    simulate_parser.add_argument('--num_adv_guards', type=int, default=0,
        help='indicates the number of adversarial guards to add')
    simulate_parser.add_argument('--num_adv_exits', type=int, default=0,
        help='indicates the number of adversarial exits to add')
    simulate_parser.add_argument('--adv_exit_policy', choices=['all', 'web', 'non-web'],
        default='all',
        help='exit policy for adversarial exits: "all" accepts all ports \
(default), "web" accepts only ports 80/443, "non-web" accepts all ports \
except 80/443')
    simulate_parser.add_argument('--other_network_modifier', default=None,
        help='class to modify network, argument syntax: module.class-argstring')
    simulate_parser.add_argument('--num_guards', type=int, default=1,
        help='indicates size of client guard list')
    simulate_parser.add_argument('--guard_expiration', type=int, default=60,
        help='indicates time in days until one-month period during which guard\
may expire, with 0 indicating no guard expiration')
    simulate_parser.add_argument('--loglevel', choices=['DEBUG', 'INFO',
        'WARNING', 'ERROR', 'CRITICAL'],
        help='set level of log messages to send to stdout, DEBUG produces testing output, quiet at all other levels', default='INFO')
        
    pathalg_subparsers = simulate_parser.add_subparsers(help='simulate\
commands', dest='pathalg_subparser')
    tor_simulate_parser = pathalg_subparsers.add_parser('tor',
        help='use vanilla Tor path selection')    
    cat_simulate_parser = pathalg_subparsers.add_parser('cat',
        help='use congestion-aware tor (Wang et al., FC12)')
    cat_simulate_parser.add_argument('--congfile', default=None,
        help='name of input congestion file')
    vcs_simulate_parser = pathalg_subparsers.add_parser('vcs',
        help='use virtual-coordinate-system path selection (Sherr, PhD 2009)')
    vcs_simulate_parser.add_argument('--congfile', default=None,
        help='name of input congestion file')
    vcs_simulate_parser.add_argument('--pdelfile', default=None,
        help='name of input propagation-delay file')
    
    concattraces_parser = subparsers.add_parser('concattraces',
        help='Combine user session traces into a single object used by \
pathsim, and pickle it. The pickled object is input to the simulate command')    
    concattraces_parser.add_argument('--out_name', default='outfilename.pickle',
        help='filename of output file')
    concattraces_parser.add_argument('--facebook_filename', 
        default='facebook.log',
        help='name of file with facebook trace')
    concattraces_parser.add_argument('--gmailchat_filename', 
        default='gmailgchat.log',
        help='name of file with gmail/gchat trace')
    concattraces_parser.add_argument('--gcalgdocs_filename', 
        default='gcalgdocs.log',
        help='name of file with gcal/gdocs trace')
    concattraces_parser.add_argument('--websearch_filename', 
        default='websearch.log',
        help='name of file with Web search trace')
    concattraces_parser.add_argument('--irc_filename', default='irc.log',
        help='name of file with IRC trace')
    concattraces_parser.add_argument('--bittorrent_filename',
        default='bittorrent.log',
        help='name of file with BitTorrent trace')

    args = parser.parse_args()

    if (args.subparser == 'process'):
        in_dirs = []
        month = args.start_month
        for year in range(args.start_year, args.end_year+1):
            while ((year < args.end_year) and (month <= 12)) or \
                (month <= args.end_month):
                if (month <= 9):
                    prepend = '0'
                else:
                    prepend = ''
                cons_dir = os.path.join(args.in_dir, 'consensuses-{0}-{1}{2}'.\
                    format(year, prepend, month))
                desc_dir = os.path.join(args.in_dir,
                    'server-descriptors-{0}-{1}{2}'.\
                    format(year, prepend, month))
                desc_out_dir = os.path.join(args.out_dir,
                    'network-state-{0}-{1}{2}'.\
                    format(year, prepend, month))
                if (not os.path.exists(desc_out_dir)):
                    os.mkdir(desc_out_dir)
                in_dirs.append((cons_dir, desc_dir, desc_out_dir))
                month += 1
            month = 1
        process_consensuses.process_consensuses(in_dirs, args.fat,
            args.initial_descriptor_dir, args.microdescs_dir)
    elif (args.subparser == 'simulate'):
        logging.basicConfig(stream=sys.stdout, level=getattr(logging,
            args.loglevel))    
        if (logger.getEffectiveLevel() == logging.DEBUG):
            logger.debug('DEBUG level detected')
            _testing = True
        else:
            _testing = False

        if (args.guard_expiration > 0):
            guard_expiration_min = args.guard_expiration*24*60*60
        else:
            # long enough that guard should never expire
            guard_expiration_min = int(100*365.25*24*60*60)

        # use arguments to adjust some TorOption parameters
        TorOptions.num_guards = args.num_guards
        TorOptions.min_num_guards = max(args.num_guards-1, 1)
        TorOptions.guard_expiration_min = guard_expiration_min
        TorOptions.guard_expiration_max = guard_expiration_min + 30*24*3600
        
        ## create iterator producing sequence of simulation network states ##
        # obtain list of network state files contained in nsf_dir
        network_state_files = []
        for dirpath, dirnames, filenames in os.walk(args.nsf_dir,
            followlinks=True):
            for filename in filenames:
                if (filename[0] != '.'):
                    network_state_files.append(os.path.join(dirpath,filename))
        # insert gaps for missing time periods
        network_state_files.sort(key = lambda x: os.path.basename(x))
        network_state_files = pad_network_state_files(network_state_files)
        # create object that will add adversarial relays into network
        adv_insertion = network_modifiers.AdversaryInsertion(args.adv_time,
            args.num_adv_guards, args.adv_guard_cons_bw, args.num_adv_exits,
            args.adv_exit_cons_bw, _testing, args.adv_exit_policy)
        network_modifiers = [adv_insertion]
        # create other network modification object
        if (args.other_network_modifier is not None):
            # dynamically import module and obtain reference to class
            full_classname, class_arg = args.other_network_modifier.split('-')
            class_components = full_classname.split('.')
            modulename = '.'.join(class_components[0:-1])
            classname = class_components[-1]
            network_modifier_module = importlib.import_module(modulename)
            network_modifier_class = getattr(network_modifier_module, classname)
            # create object of class
            other_network_modifier = network_modifier_class(args, _testing)
            network_modifiers.append(other_network_modifier)
        # create iterator that applies network modifiers to nsf list
        network_states = get_network_states(network_state_files,
            network_modifiers)

        # determine start and end times
        start_time = None
        with open(network_state_files[0]) as nsf:
            consensus = pickle.load(nsf)
            start_time = timestamp(consensus.valid_after)
        end_time = None
        with open(network_state_files[-1]) as nsf:
            consensus = pickle.load(nsf)
            end_time = timestamp(consensus.fresh_until)

        # get our stream creation model from our user traces
        # available sessions:
        #   "simple", "facebook", "gmailgchat", "gcalgdocs", "websearch", "irc",
        #   "bittorrent"
        streams = get_user_model(start_time, end_time, args.trace_file,
            session=args.user_model)

        # for alternate path-selection algorithms
        # set parameters and substitute simulation functions
        if (args.pathalg_subparser == 'tor'):
            congfilename = None
            pdelfilename = None
        elif (args.pathalg_subparser == 'cat'):
            congfilename = args.congfile
            pdelfilename = None
            create_circuit = congestion_aware_pathsim.create_circuit
            client_assign_stream = \
                congestion_aware_pathsim.client_assign_stream
        elif (args.pathalg_subparser == 'vcs'):
            congfilename = args.congfile
            pdelfilename = args.pdelfile
            create_circuits = vcs_pathsim.create_circuits
            create_circuit = vcs_pathsim.create_circuit

        congmodel = CongestionModel(congfilename)
        pdelmodel = PropagationDelayModel(pdelfilename)            

        # set up simulation output and produce header
        # dynamically import module and obtain reference to class
        output_class_components = args.output_class.split('.')
        output_modulename = '.'.join(output_class_components[0:-1])
        output_classname = output_class_components[-1]
        output_module = importlib.import_module(output_modulename)
        output_class = getattr(output_module, output_classname)
        callbacks = output_class(args.format, _testing, file=sys.stdout)
        callbacks.start()

        # simulate circuit creation and stream assignment
        # [client/dest] client_id is passed through so callbacks (e.g.
        # PrintStreamAssignments' 'network-adv' format) can report which
        # trace-file key/session each row came from. Wrapped in
        # try/except TypeError because --pathalg vcs substitutes
        # create_circuits with vcs_pathsim.create_circuits, which may not
        # accept this newer kwarg - falls back to the old call shape.
        if isinstance(streams, dict):
            network_states_list = list(network_states)
            for model_name, model_streams in streams.items():
                try:
                    create_circuits(iter(network_states_list), model_streams,
                        args.num_samples, congmodel, pdelmodel, callbacks,
                        shared_guards=args.shared_guards, client_id=model_name)
                except TypeError:
                    create_circuits(iter(network_states_list), model_streams,
                        args.num_samples, congmodel, pdelmodel, callbacks,
                        shared_guards=args.shared_guards)
        else:
            try:
                create_circuits(network_states, streams, args.num_samples,
                    congmodel, pdelmodel, callbacks,
                    shared_guards=args.shared_guards, client_id=args.user_model)
            except TypeError:
                create_circuits(network_states, streams, args.num_samples,
                    congmodel, pdelmodel, callbacks,
                    shared_guards=args.shared_guards)
    elif (args.subparser == 'concattraces'):
        ut = UserTraces(args.facebook_filename, args.gmailchat_filename,
            args.gcalgdocs_filename, args.websearch_filename,
            args.irc_filename, args.bittorrent_filename)
        ut.save_pickle(args.out_name)