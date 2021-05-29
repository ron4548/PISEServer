#!/usr/bin/env python

import angr
import logging
import time

from pise.cache import SimulationCache, ProbingCache
from pise.sym_ex_helpers import QueryStatePlugin

logger = logging.getLogger(__name__)


class QueryRunner:
    def __init__(self, file, hookers):
        self.file = file
        self.project = angr.Project(file, auto_load_libs=False)
        self.mode = None
        self.hookers = hookers
        self.set_membership_hooks()
        self.cache = SimulationCache()
        self.probing_cache = ProbingCache()

    def membership_step_by_step(self, inputs):
        logger.info('Performing membership, step by step')
        logger.debug('Query: %s' % inputs)

        # Check with probing cache if this query poses an impossible continuation
        if self.probing_cache.has_contradiction(inputs):
            logger.info('Query Answered by cache, answer is false')
            return False, None, 0, None, None

        self.set_membership_hooks()

        # Check cache if we have states available for a prefix of our query
        cached_prefix_len, cached_states = self.cache.lookup(inputs)

        if cached_states is not None:
            # If we found anything in the cache, just register those states with the monitor plugin
            logger.info('Retrieved %d states from cache, covering prefix of %d' % (len(cached_states), cached_prefix_len))
            logger.debug('States: %s' % cached_states)
            for s in cached_states:
                s.register_plugin('query', QueryStatePlugin(inputs, cached_prefix_len))

            sm = self.project.factory.simulation_manager(cached_states)
        else:
            # If we haven't find anything in cache, just start from the beginning
            logger.info('No prefix exists in cache, starting from the beginning')
            entry_state = self.project.factory.entry_state(add_options=angr.options.unicorn)
            entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            entry_state.register_plugin('query', QueryStatePlugin(inputs))
            sm = self.project.factory.simulation_manager(entry_state)

        t = time.process_time_ns()
        sm.move('active', 'position_%d' % cached_prefix_len)
        # sm.use_technique(angr.exploration_techniques.threading.Threading())
        for i in range(cached_prefix_len, len(inputs)):
            stash = "position_%d" % i
            next_stash = "position_%d" % (i + 1)

            def filter_func(state):
                return next_stash if state.query.position == i + 1 else stash

            sm.run(stash=stash, filter_func=filter_func)

            if next_stash in sm.stashes.keys():
                logger.info("Done symbol %d with %d states" % (i, len(getattr(sm, next_stash))))
                self.cache.store(inputs[:(i+1)], getattr(sm, next_stash))
            else:
                logger.error('Next stash is not available, we have no states left!')
                break

        final_stash = "position_%d" % len(inputs)
        ms_time = time.process_time_ns() - t
        if final_stash in sm.stashes.keys() and len(getattr(sm, final_stash)) > 0:
            logger.info('Membership is true - probing')

            t = time.process_time_ns()
            # Wait for all states to probe
            sm.run(stash=final_stash, filter_func=lambda sl: 'probing_done' if sl.query.done_probing else None)
            probe_time = time.process_time_ns() - t

            new_symbols = []

            # Collect all probed symbols from states that done probing
            if 'probing_done' in sm.stashes.keys():
                for s in sm.probing_done:
                    if s.query.probed_symbol is not None:
                        new_symbols.append(s.query.probed_symbol)

            # Collect pending probes from states that terminated
            for s in sm.deadended:
                if s.query.probing_pending:
                    s.query.collect_pending_probe()
                    if s.query.probed_symbol is not None:
                        new_symbols.append(s.query.probed_symbol)
            # print(new_symbols)

            # Put probing result in probing cache
            self.probing_cache.insert(inputs, new_symbols)
            return True, [sym.__dict__ for sym in new_symbols], ms_time, 0, probe_time

        # Otherwise, the membership query resulted False
        # TODO: understand if we ever get here at all. Does probing cache always prevents us from getting here?
        return False, None, ms_time, None, None

    def clear_cache(self):
        self.cache = SimulationCache()

    def set_membership_hooks(self):
        if self.mode == 'membership':
            return
        logger.info('Setting hooks')
        for hook in self.hookers:
            hook.set_hook(self.project)
        self.mode = 'membership'


