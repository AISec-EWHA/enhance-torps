import pathsim
import stem.descriptor.reader
import stem.descriptor
import stem.descriptor.microdescriptor
import stem
import os
import os.path
import datetime
import cPickle as pickle


def parse_guardfraction(r_stat):
        """stem does not parse the GuardFraction keyword on the 'w' line as a
        named attribute - it only recognizes Bandwidth/Measured/Unmeasured,
        so GuardFraction ends up in unrecognized_bandwidth_entries as the raw
        'GuardFraction=NN' string. Parse it directly here and return it as a
        float(F) in [0.0, 1.0]. Returns None if absent."""
        for entry in getattr(r_stat, 'unrecognized_bandwidth_entries', []):
                if entry.startswith('GuardFraction='):
                        try:
                                return float(entry.split('=', 1)[1]) / 100.0
                        except (ValueError, IndexError):
                                return None
        return None


def parse_ipv6_address(desc):
        """Returns the relay's IPv6 OR address as a string, or None if it has
        none. stem exposes this via or_addresses: a list of
        (address, port, is_ipv6) tuples. We take the first IPv6 entry, matching
        Tor's node_get_pref_ipv6_orport() picking the first valid IPv6 OR
        address available."""
        for entry in getattr(desc, 'or_addresses', []):
                address, port, is_ipv6 = entry
                if is_ipv6:
                        return address
        return None


def relay_supports_conflux(r_stat):
        """Returns True iff the relay advertises support for the conflux
        subprotocol (Relay=5 in the consensus 'pr' line), mirroring
        node_supports_conflux() in nodelist.c. stem parses the 'pr' line
        into r_stat.protocols, an OrderedDict mapping protocol name (e.g.
        'Relay') to an already-expanded list of supported version
        integers (so a range like 'Relay=1-5' becomes [1,2,3,4,5]) - we
        just check whether 5 is in that list."""
        protocols = getattr(r_stat, 'protocols', None)
        if not protocols:
                return False
        return 5 in protocols.get('Relay', [])


def parse_family_ids_from_microdescriptor(md):
        """Extracts the family-ids list from a stem Microdescriptor object.
        As of stem 1.8.1, 'family-ids' is NOT parsed as a named attribute (it
        was added to the dir-spec later, consensus method 35+), so it lands in
        get_unrecognized_lines() the same way GuardFraction did for the 'w'
        line. Returns a list of family ID strings (e.g. 'ed25519:AAAA...'),
        or an empty list if the microdescriptor has none.
        If a future stem version DOES parse this as a named 'family_ids'
        attribute, we prefer that (checked first) so this keeps working
        either way."""
        native = getattr(md, 'family_ids', None)
        if native:
                return list(native)
        for line in md.get_unrecognized_lines():
                if isinstance(line, bytes):
                        line = line.decode('utf-8', 'ignore')
                line = line.strip()
                if line.startswith('family-ids'):
                        parts = line.split()
                        return parts[1:]
        return []


_FAMILY_CERT_EXT_TYPE_SIGNED_WITH_ED25519_KEY = 4


def _decode_family_cert_signing_key(cert_b64):
        """Parses a single base64-encoded Ed25519 certificate blob (the body
        of one 'family-cert' PEM block, per proposal 321 / cert-spec.txt's
        v1 certificate format) and returns the family ID string derived
        from its signing key (e.g. 'ed25519:AAAA...'), or None if the cert
        is malformed or doesn't carry the required signing-key extension.

        This is a from-scratch binary parse (not using stem's certificate
        module) so it works regardless of stem version. Binary layout:
            VERSION        1 byte
            CERT_TYPE      1 byte
            EXPIRATION     4 bytes
            CERT_KEY_TYPE  1 byte
            CERTIFIED_KEY  32 bytes   (the relay's own identity key - NOT
                                        what we want)
            N_EXTENSIONS   1 byte
            EXTENSIONS     N_EXTENSIONS * (
                                EXT_LENGTH 2 bytes (big-endian)
                                EXT_TYPE   1 byte
                                EXT_FLAGS  1 byte
                                EXT_DATA   EXT_LENGTH bytes
                            )
            SIGNATURE      64 bytes (unused here)

        The family ID is the 32-byte key from the 'signed-with-ed25519-key'
        extension (type 4) - i.e. the family key (KS_familyid_ed) that
        signed this cert - NOT the CERTIFIED_KEY field (which is just the
        relay's own identity key, present in every cert regardless of
        family)."""
        import base64
        import struct
        try:
                raw = base64.b64decode(cert_b64)
        except Exception:
                return None
        header_len = 1 + 1 + 4 + 1 + 32 + 1
        if len(raw) < header_len:
                return None
        offset = 1 + 1 + 4 + 1 + 32  # skip VERSION..CERTIFIED_KEY
        n_extensions = ord(raw[offset])
        offset += 1
        for _ in range(n_extensions):
                if offset + 4 > len(raw):
                        return None
                ext_length = struct.unpack('>H', raw[offset:offset + 2])[0]
                ext_type = ord(raw[offset + 2])
                offset += 4
                ext_data = raw[offset:offset + ext_length]
                offset += ext_length
                if offset > len(raw):
                        return None
                if (ext_type == _FAMILY_CERT_EXT_TYPE_SIGNED_WITH_ED25519_KEY
                                and len(ext_data) == 32):
                        return 'ed25519:' + base64.b64encode(ext_data).rstrip('=')
        return None


import re as _re_family_cert
_FAMILY_CERT_BLOCK_RE = _re_family_cert.compile(
        r'family-cert\s*\r?\n-----BEGIN FAMILY CERT-----\r?\n'
        r'(?P<body>.*?)'
        r'\r?\n-----END FAMILY CERT-----',
        _re_family_cert.DOTALL)


def parse_family_ids_from_server_descriptor(desc, raw_text=None):
        """[Complement to parse_family_ids_from_microdescriptor()] Extracts
        family IDs from a stem RelayDescriptor's 'family-cert' entries.

        WHY THIS EXISTS: per proposal 321 ('Happy Families'), a
        microdescriptor's family-ids line is just a compressed summary
        DERIVED from the server descriptor's family-cert entries. The
        server descriptor is the original source. Crucially, server
        descriptors get republished by relays roughly every 18 hours
        REGARDLESS of whether anything changed, whereas microdescriptors
        are content-addressed and only get a new archive entry when their
        content actually changes (sometimes not for a year+). So reading
        family-cert straight from server descriptors (which we're already
        downloading for other purposes) gives much denser time coverage
        than relying on microdescs alone - no extra downloads needed.

        HOW: rather than going through stem's get_unrecognized_lines()
        (an earlier version of this function did that, assuming it
        reconstructs unrecognized PEM-style blocks as consecutive line
        entries the way it does for recognized blocks like 'onion-key' -
        that assumption turned out to be wrong: it consistently returned
        zero matches even on a dataset where the corresponding
        microdescriptor family-ids DID show ~1.8M non-empty hits, which
        can only happen if the underlying server descriptors actually had
        family-cert content), this regex-scans the descriptor's own raw
        text directly (str(desc), which stem's descriptor classes return
        as the original verbatim bytes read from disk - the same
        mechanism this file's 'fat' output mode already relies on via
        `desc.type_annotation + str(desc)` to reproduce descriptors
        byte-for-byte). Scanning the raw text sidesteps any uncertainty
        about how stem buckets not-yet-parsed keywords internally.

        raw_text: optional pre-computed str(desc) - pass this in if the
        caller already has it (see read_descriptors()) to avoid
        re-stringifying the same descriptor twice.

        A descriptor may have zero, one, or multiple 'family-cert' blocks
        (spec allows up to 3). Returns a list of family ID strings, one
        per valid cert found (deduplicated), or [] if none.

        REMAINING CAVEAT: this does not cryptographically verify the
        cert's signature, expiration, or certified-key match the way a
        directory authority does before deriving microdescriptor
        family-ids - see the WARNING at this function's call site in
        process_consensuses() about cross-checking family_cert_merged
        against has_family_ids before trusting this as a sole source."""
        native = getattr(desc, 'family_cert_ids', None)
        if native:
                return list(native)
        if raw_text is None:
                try:
                        raw_text = str(desc)
                except Exception:
                        return []
        if isinstance(raw_text, bytes):
                raw_text = raw_text.decode('utf-8', 'ignore')
        family_ids = []
        for match in _FAMILY_CERT_BLOCK_RE.finditer(raw_text):
                body = ''.join(match.group('body').split())
                family_id = _decode_family_cert_signing_key(body)
                if family_id and family_id not in family_ids:
                        family_ids.append(family_id)
        return family_ids


def build_microdesc_consensus_index(microdescs_dir):
        """[Nearest-match fallback] Walks microdescs_dir once and builds a
        sorted list of (datetime, path) for every file matching
        CollecTor's 'YYYY-MM-DD-HH-MM-SS-consensus-microdesc' naming
        convention, anywhere in the tree (however many months' worth of
        archives are nested under it). Used so get_family_ids_for_period()
        can fall back to the *nearest available* consensus-microdesc file
        when the exact hour is missing (e.g. a gap in the microdescs
        archive that doesn't line up with the ns-consensus archive's
        coverage) - since almost all relays' microdescriptor digests
        don't change hour to hour, an adjacent hour is usually still
        accurate."""
        import re
        pattern = re.compile(
                r'^(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})-consensus-microdesc$')
        index = []
        for dirpath, dirnames, fnames in os.walk(microdescs_dir):
                for fname in fnames:
                        m = pattern.match(fname)
                        if m:
                                dt = datetime.datetime.strptime(
                                        m.group(1), '%Y-%m-%d-%H-%M-%S')
                                index.append((dt, os.path.join(dirpath, fname)))
        index.sort(key=lambda pair: pair[0])
        print('Indexed {0} consensus-microdesc files under {1}.'.format(
                len(index), microdescs_dir))
        return index


def find_nearest_microdesc_consensus(cons_valid_after, index):
        """Returns (path, drift_seconds) for the entry in index (as built by
        build_microdesc_consensus_index()) closest in time to
        cons_valid_after, or (None, None) if index is empty. drift_seconds
        is signed: positive if the match is *after* cons_valid_after."""
        if not index:
                return None, None
        best = min(index, key=lambda pair: abs(
                (pair[0] - cons_valid_after).total_seconds()))
        drift = (best[0] - cons_valid_after).total_seconds()
        return best[1], drift


def read_microdescriptors_family_ids(digest_to_family_ids, all_digests_seen,
        microdescs_dir, skip_listener):
        """Reads every microdescriptor anywhere under microdescs_dir
        (fully recursive) and populates digest_to_family_ids as
        {microdescriptor_digest: [family_id, ...]}, AND populates
        all_digests_seen with every microdescriptor digest read regardless
        of whether it had family-ids. digest_to_family_ids only stores
        digests that DO have family-ids, so all_digests_seen is what lets
        get_family_ids_for_period() distinguish "digest genuinely missing
        from the archive" from "digest present, just has no family-ids" -
        conflating the two used to make digest_missing count nearly every
        relay, since most relays don't declare family-ids at all. Mirrors
        the existing
        in-memory map that's reused across all consensus periods, since
        the same microdescriptor content (and thus digest) is typically
        referenced by many hourly microdesc-consensuses in a row.

        NOTE ON DIRECTORY STRUCTURE: microdescs_dir can be *any* parent
        folder containing one or more extracted CollecTor microdescs
        archives in whatever nested layout they came in (e.g. if you
        extracted several months' worth of monthly archives side by side,
        each with its own 'consensus-microdesc/' and 'micro/'
        subdirectories at some nested path) - this walks the *entire*
        tree and filters by object type, so the exact directory layout
        and how many months are present doesn't matter. Non-microdescriptor
        files encountered along the way (e.g. consensus-microdesc files
        living in the same tree) are silently skipped via the isinstance
        check below, rather than assuming a single specific 'micro'
        subfolder exists directly under microdescs_dir.

        NOTE ON DIGEST ENCODING (needs empirical verification): we compute
        each microdescriptor's digest with stem's default (SHA256/BASE64 as
        of stem 1.8.0's digest() method), and assume this matches the
        encoding of RouterStatusEntryMicroV3.microdescriptor_digest in the
        corresponding consensus-microdesc file. If lookups come up empty
        when merging, print a sample of both to confirm the encoding lines
        up before trusting the family ID results.

        NOTE ON descriptor_type: individual per-descriptor files in
        archive-format CollecTor dumps (the 'micro/<hash-prefix>/<hash-prefix>/
        <digest>' layout) have no file extension and no '@type' header
        line, so stem can't auto-detect their type from content and
        raises a TypeError internally, which DescriptorReader then
        reports (confusingly) as "Unrecognized mime type: None (None)".
        We work around this by passing descriptor_type explicitly, so no
        auto-detection is needed for these files. This also means any
        consensus-microdesc files encountered while walking the same tree
        will be (correctly) skipped as a type mismatch, rather than mixed
        in with actual microdescriptors."""
        num_microdescs = 0
        num_items_seen = 0
        num_files_seen = [0]
        print('Reading microdescriptors from: {0}'.format(microdescs_dir))
        print('(scanning directory tree for files - for large/compressed '
              'archives this can take a while before the first progress '
              'line below appears; it is not stuck)')

        def read_listener(path):
                # Fires once per FILE opened by the reader (not once per
                # descriptor/microdescriptor within it), so this prints
                # even while we're churning through a long run of
                # consensus-microdesc files that all get filtered out
                # below - without this, progress can look "stuck" for a
                # long time since num_microdescs only counts actual
                # Microdescriptor instances.
                num_files_seen[0] += 1
                if (num_files_seen[0] % 50 == 0) or (num_files_seen[0] == 1):
                        print('  [{0} files opened so far] currently reading: {1}'.format(
                                num_files_seen[0], path))

        reader = stem.descriptor.reader.DescriptorReader(microdescs_dir,
                validate=True, descriptor_type='microdescriptor 1.0')
        reader.register_skip_listener(skip_listener)
        reader.register_read_listener(read_listener)
        with reader:
                for md in reader:
                        num_items_seen += 1
                        if (num_items_seen % 5000 == 0):
                                print('  ...{0} total descriptor items seen '
                                        '({1} were microdescriptors so far)'.format(
                                                num_items_seen, num_microdescs))
                        if not isinstance(md, stem.descriptor.microdescriptor.Microdescriptor):
                                # This tree also contains consensus-microdesc
                                # files (or other descriptor types) mixed in
                                # alongside the actual microdescriptors -
                                # skip anything that isn't a Microdescriptor.
                                continue
                        num_microdescs += 1
                        if (num_microdescs % 10000 == 0):
                                print('{0} microdescriptors processed.'.format(num_microdescs))
                        all_digests_seen.add(md.digest())
                        family_ids = parse_family_ids_from_microdescriptor(md)
                        if family_ids:
                                digest_to_family_ids[md.digest()] = family_ids
        print('#microdescriptors read: {0}'.format(num_microdescs))


def get_family_ids_for_period(cons_valid_after, microdesc_consensus_index,
        digest_to_family_ids, all_digests_seen, skip_listener):
        """Returns (fingerprint_to_family_ids, stats) for the microdesc-flavored
        consensus closest in time to cons_valid_after (the period the
        ns-flavor consensus currently being processed by
        process_consensuses() belongs to).

        microdesc_consensus_index: the list built by
        build_microdesc_consensus_index() - built once up front and reused
        across every period, rather than walking the directory tree again
        on every single call.

        NEAREST-MATCH FALLBACK: unlike an exact-filename lookup, this picks
        whichever indexed consensus-microdesc file is closest in time to
        cons_valid_after, even if it isn't an exact hour match. This is a
        reasonable approximation because a relay's microdescriptor digest
        (and thus its family-ids) rarely changes hour to hour - so a
        neighboring hour is usually still correct. stats['drift_seconds']
        reports how far off the match was, so you can sanity check this
        assumption over your dataset (a consistently large drift means
        your microdescs coverage doesn't overlap well with your
        ns-consensus period at all, which nearest-matching can't fix).

        fingerprint_to_family_ids: {fingerprint: [family_id, ...]}

        stats: dict with diagnostic counters for this period -
          'total_routers': how many relays we tried to look up
          'digest_missing': how many relays had a microdescriptor_digest
              that we could NOT find in all_digests_seen (i.e. that exact
              microdescriptor content was never read from the 'micro'
              archive at all - a real coverage gap). This does NOT include
              relays whose digest was found but simply had no family-ids
              (that's normal - most relays don't declare family). This is
              the number to watch: if it's high, you need to download a
              wider microdescs date range.
          'has_family_ids': how many relays had a family-ids entry (out of
              the ones whose digest we DID find - not a measure of "no
              family", since a found-but-empty family-ids is legitimate).
          'found_via_nearest': of the relays whose digest WAS found, how
              many were looked up against a nearest-match substitute file
              (drift_seconds != 0) rather than an exact-hour file. These
              are still counted as found/has_family_ids as normal - this
              is purely an informational breakdown of how much of the
              "found" total came from a time-substituted file vs an exact
              match.
          'drift_seconds': how far (in seconds, signed) the matched
              consensus-microdesc file's timestamp was from cons_valid_after.
              0 if no matching file was available at all (see below).

        Returns ({}, stats) with all-zero stats (drift_seconds included)
        and a warning if the index is completely empty - e.g. if
        microdescs_dir had no consensus-microdesc files under it at all."""
        stats = {'total_routers': 0, 'digest_missing': 0,
                'has_family_ids': 0, 'drift_seconds': 0,
                'found_via_nearest': 0}

        match_path, drift = find_nearest_microdesc_consensus(
                cons_valid_after, microdesc_consensus_index)
        if match_path is None:
                print('WARNING: microdesc_consensus_index is empty - no '
                        'consensus-microdesc files found anywhere under '
                        'the given microdescs_dir. Family IDs will be '
                        'empty for period {0}.'.format(cons_valid_after))
                return {}, stats
        stats['drift_seconds'] = drift
        if drift != 0:
                print('NOTE: nearest consensus-microdesc for period {0} is '
                        '{1:+.1f} hours off ({2}).'.format(
                                cons_valid_after, drift / 3600.0, match_path))

        fingerprint_to_family_ids = {}
        with open(match_path, 'rb') as f:
                for document in stem.descriptor.parse_file(f, validate=True,
                        document_handler='DOCUMENT'):
                        for fprint, r_stat in document.routers.iteritems():
                                stats['total_routers'] += 1
                                # Verified against a real consensus-microdesc
                                # file: 'microdescriptor_digest' is the
                                # correct attribute and matches
                                # Microdescriptor.digest() (SHA256/BASE64)
                                # exactly. Do NOT fall back to a generic
                                # '.digest' attribute if this is missing -
                                # that's a different value entirely (looks
                                # like a SHA256 hex digest of something
                                # else) and would silently produce wrong
                                # matches.
                                digest = getattr(r_stat,
                                        'microdescriptor_digest', None)
                                if digest is None:
                                        continue
                                # Judge presence against the FULL set of
                                # digests ever read from the micro/ archive,
                                # not against digest_to_family_ids (which
                                # only holds digests that had family-ids).
                                # Otherwise every relay without family-ids
                                # - the vast majority - would wrongly count
                                # as a coverage gap.
                                if digest not in all_digests_seen:
                                        # This relay's microdescriptor was
                                        # never seen in the 'micro' archive
                                        # we read at all - a real coverage
                                        # gap (see docstring).
                                        stats['digest_missing'] += 1
                                elif drift != 0:
                                        # Digest genuinely found, but this
                                        # period was matched via a nearby
                                        # substitute file rather than an
                                        # exact-hour one - still counts as
                                        # found, just tracked separately.
                                        stats['found_via_nearest'] += 1
                                family_ids = digest_to_family_ids.get(digest, [])
                                if family_ids:
                                        fingerprint_to_family_ids[fprint] = family_ids
                                        stats['has_family_ids'] += 1
        return fingerprint_to_family_ids, stats


def read_descriptors(descriptors, descriptor_dir, skip_listener):
        """Add to descriptors contents of descriptor archive in descriptor_dir."""

        num_descriptors = 0
        num_relays = 0
        num_descriptors_with_family_cert = 0
        num_descriptors_containing_family_cert_string = 0
        print('Reading descriptors from: {0}'.format(descriptor_dir))
        reader = stem.descriptor.reader.DescriptorReader(descriptor_dir,
            validate=True)
        reader.register_skip_listener(skip_listener)
        # use read listener to store metrics type annotation, which is otherwise discarded
        cur_type_annotation = [None]
        def read_listener(path):
            f = open(path)
            # store initial metrics type annotation
            initial_position = f.tell()
            first_line = f.readline()
            f.seek(initial_position)
            if (first_line[0:5] == '@type'):
                cur_type_annotation[0] = first_line
            else:
                cur_type_annotation[0] = None
            f.close()
        reader.register_read_listener(read_listener)
        with reader:
            for desc in reader:
                if (num_descriptors % 10000 == 0):
                    print('{0} descriptors processed.'.format(num_descriptors))
                num_descriptors += 1
                if (desc.fingerprint not in descriptors):
                    descriptors[desc.fingerprint] = {}
                    num_relays += 1
                    # stuff type annotation into stem object
                desc.type_annotation = cur_type_annotation[0]
                # Stuff Happy Families (proposal 321) family IDs from any
                # 'family-cert' entries onto the stem object too - see
                # parse_family_ids_from_server_descriptor() for why this is
                # a much more reliably-covered source than microdescriptor
                # family-ids (server descriptors get republished ~every 18h
                # regardless of change, so there's no archival-gap problem
                # here the way there is for microdescs).
                try:
                    raw_desc_text = str(desc)
                except Exception:
                    raw_desc_text = ''
                # Diagnostic only: counts descriptors where the literal
                # 'family-cert' keyword shows up ANYWHERE in the raw text,
                # regardless of whether we successfully parsed a cert out
                # of it. If this stays 0 while microdescriptor
                # has_family_ids is clearly nonzero, that means this
                # dataset's server-descriptor raw text genuinely doesn't
                # carry family-cert content (a real data/version issue,
                # not a parsing bug) - if this is nonzero but
                # family_cert_merged still comes out 0, the bug is in
                # _FAMILY_CERT_BLOCK_RE's exact formatting assumptions.
                if 'family-cert' in raw_desc_text:
                    num_descriptors_containing_family_cert_string += 1
                desc.family_cert_ids = parse_family_ids_from_server_descriptor(
                    desc, raw_desc_text)
                if desc.family_cert_ids:
                    num_descriptors_with_family_cert += 1
                descriptors[desc.fingerprint]\
                    [pathsim.timestamp(desc.published)] = desc
        print('#descriptors: {0}; #relays:{1}; #descriptors containing the '
            'literal "family-cert" string: {2}; #descriptors with a '
            'successfully parsed family-cert: {3}'.format(
                num_descriptors, num_relays,
                num_descriptors_containing_family_cert_string,
                num_descriptors_with_family_cert))


def process_consensuses(in_dirs, fat, initial_descriptor_dir,
        microdescs_dir=None):
    """For every input consensus, finds the descriptors published most recently before the descriptor times listed for the relays in that consensus, records state changes indicated by descriptors published during the consensus fresh period, and writes out pickled consensus and descriptor objects with the relevant information.
        Inputs:
            in_dirs: list of (consensus in dir, descriptor in dir,
                processed descriptor out dir) triples *in order*
            fat: Whether to use "fat" (aka full) representation or custom slim classes
            initial_descriptor_dir: Contains descriptors to initialize processing.
            microdescs_dir: Optional. Path to a parent folder containing
                one or more extracted CollecTor 'microdescs' archives
                (each internally containing 'consensus-microdesc/' and
                'micro/' subdirectories at some nested depth - e.g. if you
                extracted several months' worth of monthly archives, point
                this at their common parent directory; the whole tree is
                searched recursively, so it doesn't matter how many
                months are present or how they're nested). Used only to
                derive family IDs (Happy Families / Proposal 321) for
                family-conflict checks. Since microdescriptors are only
                re-published when their content changes (often not for
                months), you'll typically need this to cover a *much*
                wider date range than the consensuses/server-descriptors
                you're processing - see the family ID coverage summary
                printed at the end of this function to check whether your
                range is wide enough (a high 'digest_missing' percentage
                means you need to add earlier months). If microdescs_dir
                is None, family_ids is left empty for every relay (i.e.
                only the older declared-family check applies).
    """
    descriptors = {}
    # {microdescriptor_digest: [family_id, ...]}, built once and reused
    # across every consensus period, since read_microdescriptors_family_ids()
    # reads the whole 'micro' archive into memory up front (mirrors how
    # 'descriptors' is built once from server descriptors).
    digest_to_family_ids = {}
    # Every microdescriptor digest read from the 'micro' archive,
    # regardless of whether it had family-ids - used by
    # get_family_ids_for_period() to tell "digest genuinely missing from
    # the archive" apart from "digest present, just no family-ids"
    # (digest_to_family_ids alone can't do that since it only stores
    # digests that DO have family-ids).
    all_digests_seen = set()
    # {consensus-microdesc index}, built once (see
    # build_microdesc_consensus_index()) and reused for nearest-match
    # lookups across every consensus period.
    microdesc_consensus_index = []
    # {fingerprint: [family_id, ...]}, carried forward across periods in
    # chronological order (in_dirs/pathnames are processed in order).
    # Once a relay's family-ids is successfully resolved in ANY period
    # (its digest was actually present in the downloaded micro/ archive),
    # we keep reusing that value for later periods where the digest
    # lookup misses - e.g. because the archive doesn't happen to contain
    # that exact still-unchanged digest for every period. Family
    # membership essentially never changes hour-to-hour, so this recovers
    # a lot of real coverage *without* downloading additional history.
    # It can't help periods *before* the first period where a relay was
    # ever successfully resolved - that portion of the gap genuinely
    # requires older microdescs data if you need it closed.
    fingerprint_family_ids_cache = {}
    # Running totals across every period processed, for the coverage
    # diagnostic printed at the end (see get_family_ids_for_period()).
    family_id_stats_total = {'total_routers': 0, 'digest_missing': 0,
        'has_family_ids': 0, 'periods_with_drift': 0,
        'max_drift_seconds': 0, 'found_via_nearest': 0,
        'filled_from_cache': 0,
        # Independent of microdescs_dir - tracks how often family IDs
        # parsed from server descriptors' family-cert entries (see
        # parse_family_ids_from_server_descriptor()) got merged into a
        # relay's family_ids. Counted whenever not fat, regardless of
        # whether microdescs_dir was given.
        'family_cert_merged': 0, 'family_cert_merge_failed': 0,
        # The actual combined ("union") coverage after merging BOTH
        # sources into relays[fprint].family_ids - i.e. what fraction of
        # relay-periods end up with *some* non-empty family_ids at all,
        # regardless of which source(s) contributed it. has_family_ids
        # and family_cert_merged on their own can't answer this since
        # they may overlap (same relay-period resolved by both sources).
        'total_relay_periods_seen': 0, 'relay_periods_with_any_family_ids': 0}
    def skip_listener(path, exception):
        print('ERROR [{0}]: {1}'.format(path.encode('ascii', 'ignore'), exception.__unicode__().encode('ascii','ignore')))
        
    if fat:
        print('Outputting fat classes.')
        
    # initialize descriptors
    if (initial_descriptor_dir is not None):
        read_descriptors(descriptors, initial_descriptor_dir, skip_listener)

    if (microdescs_dir is not None):
        read_microdescriptors_family_ids(digest_to_family_ids,
            all_digests_seen, microdescs_dir, skip_listener)
        microdesc_consensus_index = build_microdesc_consensus_index(
            microdescs_dir)
        
    for in_consensuses_dir, in_descriptors, desc_out_dir in in_dirs:
                # read all descriptors into memory        
        read_descriptors(descriptors, in_descriptors, skip_listener)

        # output pickled consensuses, dict of most recent descriptors, and 
        # list of hibernation status changes
        num_consensuses = 0
        pathnames = []
        for dirpath, dirnames, fnames in os.walk(in_consensuses_dir):
            for fname in fnames:
                pathnames.append(os.path.join(dirpath,fname))
        pathnames.sort()
        for pathname in pathnames:
            filename = os.path.basename(pathname)
            if (filename[0] == '.'):
                continue
            
            print('Processing consensus file {0}'.format(filename))
            cons_f = open(pathname, 'rb')

            # store metrics type annotation line
            initial_position = cons_f.tell()
            first_line = cons_f.readline()
            if (first_line[0:5] == '@type'):
                type_annotation = first_line
            else:
                type_annotation = None
            cons_f.seek(initial_position)

            descriptors_out = dict()
            hibernating_statuses = [] # (time, fprint, hibernating)
            cons_valid_after = None
            cons_fresh_until = None
            if not fat:
                cons_bw_weights = None
                cons_bwweightscale = None
                relays = {}
            num_not_found = 0
            num_found = 0
            # read in consensus document
            i = 0
            for document in stem.descriptor.parse_file(cons_f, validate=True,
                document_handler='DOCUMENT'):
                if (i > 0):
                    raise ValueError('Unexpectedly found more than one consensus in file: {}'.\
                        format(pathname))
                if (cons_valid_after == None):
                    cons_valid_after = document.valid_after
                    # compute timestamp version once here
                    valid_after_ts = pathsim.timestamp(cons_valid_after)
                if (cons_fresh_until == None):
                    cons_fresh_until = document.fresh_until
                    # compute timestamp version once here
                    fresh_until_ts = pathsim.timestamp(cons_fresh_until)
                if not fat:
                    if (cons_bw_weights == None):
                        cons_bw_weights = document.bandwidth_weights
                    if (cons_bwweightscale == None) and \
                        ('bwweightscale' in document.params):
                        cons_bwweightscale = document.params[\
                                'bwweightscale']
                    if (microdescs_dir is not None):
                        family_id_map, family_id_stats = get_family_ids_for_period(
                            cons_valid_after, microdesc_consensus_index,
                            digest_to_family_ids, all_digests_seen, skip_listener)
                        family_id_stats_total['total_routers'] += \
                            family_id_stats['total_routers']
                        family_id_stats_total['digest_missing'] += \
                            family_id_stats['digest_missing']
                        family_id_stats_total['has_family_ids'] += \
                            family_id_stats['has_family_ids']
                        family_id_stats_total['found_via_nearest'] += \
                            family_id_stats['found_via_nearest']
                        if family_id_stats['drift_seconds'] != 0:
                            family_id_stats_total['periods_with_drift'] += 1
                        family_id_stats_total['max_drift_seconds'] = max(
                            family_id_stats_total['max_drift_seconds'],
                            abs(family_id_stats['drift_seconds']))
                        # Feed this period's resolved (non-empty) results
                        # into the cross-period cache for later periods to
                        # fall back on.
                        fingerprint_family_ids_cache.update(family_id_map)
                    else:
                        family_id_map = {}
                    for fprint, r_stat in document.routers.iteritems():
                        resolved_family_ids = family_id_map.get(fprint)
                        if resolved_family_ids is None:
                            # Not resolved this period - fall back to the
                            # most recent earlier period where it WAS
                            # resolved, if any (see
                            # fingerprint_family_ids_cache comment above).
                            resolved_family_ids = fingerprint_family_ids_cache.get(
                                fprint, [])
                            if resolved_family_ids:
                                family_id_stats_total['filled_from_cache'] += 1
                        relays[fprint] = pathsim.RouterStatusEntry(fprint, r_stat.nickname,
                            r_stat.flags, r_stat.bandwidth,
                            parse_guardfraction(r_stat),
                            resolved_family_ids,
                            relay_supports_conflux(r_stat))
                consensus = document
                i += 1
                            

            # find relays' most recent unexpired descriptor published
            # before the publication time in the consensus
            # and status changes in fresh period (i.e. hibernation)
            for fprint, r_stat in consensus.routers.iteritems():
                pub_time = pathsim.timestamp(r_stat.published)
                desc_time = 0
                descs_while_fresh = []
                desc_time_fresh = None
                # get all descriptors with this fingerprint
                if (r_stat.fingerprint in descriptors):
                    for t,d in descriptors[r_stat.fingerprint].items():
                        # update most recent desc seen before cons pubtime
                        # allow pubtime after valid_after but not fresh_until
                        if (valid_after_ts-t <\
                            pathsim.TorOptions.router_max_age) and\
                            (t <= pub_time) and (t > desc_time) and\
                            (t <= fresh_until_ts):
                            desc_time = t
                        # store fresh-period descs for hibernation tracking
                        if (t >= valid_after_ts) and \
                            (t <= fresh_until_ts):
                            descs_while_fresh.append((t,d))                                
                        # find most recent hibernating stat before fresh period
                        # prefer most-recent descriptor before fresh period
                        # but use oldest after valid_after if necessary
                        if (desc_time_fresh == None):
                            desc_time_fresh = t
                        elif (desc_time_fresh < valid_after_ts):
                            if (t > desc_time_fresh) and\
                                (t <= valid_after_ts):
                                desc_time_fresh = t
                        else:
                            if (t < desc_time_fresh):
                                desc_time_fresh = t

                # output best descriptor if found
                if (desc_time != 0):
                    num_found += 1
                    # store discovered recent descriptor
                    desc = descriptors[r_stat.fingerprint][desc_time]
                    if not fat:
                        descriptors_out[r_stat.fingerprint] = \
                            pathsim.ServerDescriptor(desc.fingerprint, \
                                desc.hibernating, desc.nickname, \
                                desc.family, desc.address, \
                                desc.exit_policy, desc.ntor_onion_key, \
                                parse_ipv6_address(desc))
                        # Merge in family IDs parsed from this descriptor's
                        # family-cert entries (see
                        # parse_family_ids_from_server_descriptor()). This
                        # reuses the "most recent unexpired descriptor"
                        # match this loop already computed, and is a much
                        # denser source than the microdescriptor-based
                        # family_id_map used when relays[fprint] was first
                        # built further up (server descriptors get
                        # republished ~every 18h regardless of change).
                        cert_family_ids = getattr(desc, 'family_cert_ids', [])
                        if cert_family_ids and (r_stat.fingerprint in relays):
                            entry = relays[r_stat.fingerprint]
                            merged_family_ids = sorted(
                                set(getattr(entry, 'family_ids', []) or [])
                                | set(cert_family_ids))
                            try:
                                entry.family_ids = merged_family_ids
                                family_id_stats_total['family_cert_merged'] += 1
                            except AttributeError:
                                # pathsim.RouterStatusEntry may not support
                                # attribute assignment (e.g. if it's a
                                # namedtuple) - skip rather than guess at
                                # how to reconstruct it. If this warning
                                # shows up a lot, check
                                # pathsim.RouterStatusEntry's definition
                                # and adjust this block (e.g. rebuild via
                                # pathsim.RouterStatusEntry._replace(...)
                                # if it's a namedtuple).
                                if family_id_stats_total['family_cert_merge_failed'] == 0:
                                    print('WARNING: could not set family_ids on '
                                        'RouterStatusEntry (immutable?) - '
                                        'family-cert data will not be merged in. '
                                        'See comment at this warning in '
                                        'process_consensuses.py.')
                                family_id_stats_total['family_cert_merge_failed'] += 1
                    else:
                        if (desc.type_annotation is not None):
                            descriptors_out[r_stat.fingerprint] = desc.type_annotation + str(desc)
                        else:
                            descriptors_out[r_stat.fingerprint] = str(desc)
                     
                    # store hibernating statuses
                    if (desc_time_fresh == None):
                        raise ValueError('Descriptor error for {0}:{1}.\n Found  descriptor before published date {2}: {3}\nDid not find descriptor for initial hibernation status for fresh period starting {4}.'.format(r_stat.nickname, r_stat.fingerprint, pub_time, desc_time, valid_after_ts))
                    desc = descriptors[r_stat.fingerprint][desc_time_fresh]
                    cur_hibernating = desc.hibernating
                    # setting initial status
                    hibernating_statuses.append((0, desc.fingerprint,\
                        cur_hibernating))
                    if (cur_hibernating):
                        print('{0}:{1} was hibernating at consenses period start'.format(desc.nickname, desc.fingerprint))
                    descs_while_fresh.sort(key = lambda x: x[0])
                    for (t,d) in descs_while_fresh:
                        if (d.hibernating != cur_hibernating):
                            cur_hibernating = d.hibernating                                   
                            hibernating_statuses.append(\
                                (t, d.fingerprint, cur_hibernating))
                            if (cur_hibernating):
                                print('{0}:{1} started hibernating at {2}'\
                                    .format(d.nickname, d.fingerprint, t))
                            else:
                                print('{0}:{1} stopped hibernating at {2}'\
                                    .format(d.nickname, d.fingerprint, t))                   
                else:
#                            print(\
#                            'Descriptor not found for {0}:{1}:{2}'.format(\
#                                r_stat.nickname,r_stat.fingerprint, pub_time))
                    num_not_found += 1

            # Count real combined ("union") family_ids coverage for this
            # period, after both the microdesc-based and family-cert-based
            # merges above are done - see 'total_relay_periods_seen' /
            # 'relay_periods_with_any_family_ids' comment at
            # family_id_stats_total's definition.
            if not fat:
                for entry in relays.values():
                    family_id_stats_total['total_relay_periods_seen'] += 1
                    if entry.family_ids:
                        family_id_stats_total['relay_periods_with_any_family_ids'] += 1

            # output pickled consensus, recent descriptors, and
            # hibernating status changes
            if (cons_valid_after != None) and\
                (cons_fresh_until != None):
                if not fat:
                    consensus_out = pathsim.NetworkStatusDocument(\
                        cons_valid_after, cons_fresh_until, cons_bw_weights,\
                        cons_bwweightscale, relays)
                else:
                    if (type_annotation is not None):
                        consensus_out = type_annotation + str(consensus)
                    else:
                        consensus_out = str(consensus)
                hibernating_statuses.sort(key = lambda x: x[0],\
                    reverse=True)
                outpath = os.path.join(desc_out_dir,\
                    cons_valid_after.strftime(\
                        '%Y-%m-%d-%H-%M-%S-network_state'))
                f = open(outpath, 'wb')
                pickle.dump(consensus_out, f, pickle.HIGHEST_PROTOCOL)
                pickle.dump(descriptors_out,f,pickle.HIGHEST_PROTOCOL)
                pickle.dump(hibernating_statuses,f,pickle.HIGHEST_PROTOCOL)
                f.close()

                print('Wrote descriptors for {0} relays.'.\
                    format(num_found))
                print('Did not find descriptors for {0} relays\n'.\
                    format(num_not_found))
            else:
                print('Problem parsing {0}.'.format(filename))             
            num_consensuses += 1
            
            cons_f.close()
                
        print('# consensuses: {0}'.format(num_consensuses))

    if (microdescs_dir is not None):
        total = family_id_stats_total['total_routers']
        missing = family_id_stats_total['digest_missing']
        found = family_id_stats_total['has_family_ids']
        pct_missing = (100.0 * missing / total) if total else 0.0
        print('')
        print('=== Family ID coverage summary (across all periods) ===')
        print('Total (relay, period) lookups attempted: {0}'.format(total))
        print('Microdescriptor digest NOT found in micro/ archive: {0} '
            '({1:.1f}%) <- if this is high, download an earlier/wider '
            'microdescs date range; these are coverage gaps, not '
            'evidence of "no family"'.format(missing, pct_missing))
        print('Relays with a non-empty family-ids entry found: {0}'.format(
            found))
        print('Additionally filled in from an earlier period via the '
            'cross-period cache (digest missing THIS period, but this '
            'relay was resolved in an earlier one): {0}'.format(
                family_id_stats_total['filled_from_cache']))
        print('Of the found digests, matched via a nearest (non-exact-hour) '
            'substitute file: {0}'.format(
                family_id_stats_total['found_via_nearest']))
        print('Periods where the nearest consensus-microdesc file was not '
            'an exact hour match: {0}'.format(
                family_id_stats_total['periods_with_drift']))
        print('Largest such drift seen: {0:.1f} hours'.format(
            family_id_stats_total['max_drift_seconds'] / 3600.0))

    if not fat:
        print('')
        print('=== family-cert (server descriptor) coverage summary ===')
        print('Relay-periods where family IDs from a family-cert entry '
            'were merged in: {0}'.format(
                family_id_stats_total['family_cert_merged']))
        if family_id_stats_total['family_cert_merge_failed'] > 0:
            print('Relay-periods where a family-cert was found but could '
                'NOT be merged (RouterStatusEntry assignment failed - see '
                'WARNING above): {0}'.format(
                    family_id_stats_total['family_cert_merge_failed']))
        print('')
        print('=== COMBINED family_ids coverage (both sources merged) ===')
        total_rp = family_id_stats_total['total_relay_periods_seen']
        any_ids = family_id_stats_total['relay_periods_with_any_family_ids']
        pct_any = (100.0 * any_ids / total_rp) if total_rp else 0.0
        print('Total relay-periods seen: {0}'.format(total_rp))
        print('Relay-periods with a non-empty family_ids from EITHER '
            'source after merging: {0} ({1:.1f}%)'.format(any_ids, pct_any))