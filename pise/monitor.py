#!/usr/bin/env python

import angr
import logging
import time
from pise import membership
from pise.cache import SimulationCache, ProbingCache

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
        if self.probing_cache.has_contradiction(inputs):
            logger.info('Query Answered by cache, answer is false')
            return False, None, 0, None, None
        self.set_membership_hooks()
        cached_prefix, cached_states = self.cache.lookup(inputs)

        if cached_states is not None:
            logger.info('Retrieved %d states from cache, covering prefix of %d' % (len(cached_states), cached_prefix))
            logger.debug('States: %s' % cached_states)
            for s in cached_states:
                s.register_plugin('monitor', membership.MonitorStatePlugin(inputs, cached_prefix))

            sm = self.project.factory.simulation_manager(cached_states)
        else:
            logger.info('No prefix exists in cache, starting from the beginning')
            entry_state = self.project.factory.entry_state(add_options=angr.options.unicorn)
            entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            entry_state.register_plugin('monitor', membership.MonitorStatePlugin(inputs))
            sm = self.project.factory.simulation_manager(entry_state)

        t = time.process_time_ns()
        sm.move('active', 'position_%d' % cached_prefix)
        # sm.use_technique(angr.exploration_techniques.threading.Threading())
        for i in range(cached_prefix, len(inputs)):
            stash = "position_%d" % i
            next_stash = "position_%d" % (i + 1)

            def filter_func(state):
                return next_stash if state.monitor.position == i + 1 else stash

            sm.run(stash=stash, filter_func=filter_func)

            if next_stash in sm.stashes.keys():
                logger.info("Done symbol %d with %d states" % (i, len(getattr(sm, next_stash))))
                self.cache.store(inputs[:(i+1)], getattr(sm, next_stash))

        final_stash = "position_%d" % len(inputs)
        ms_time = time.process_time_ns() - t
        if final_stash in sm.stashes.keys() and len(getattr(sm, final_stash)) > 0:
            logger.info('Membership is true - probing')

            t = time.process_time_ns()
            # Wait for all states to probe
            sm.run(stash=final_stash, filter_func=lambda sl: 'probing_done' if sl.monitor.done_probing else None)
            probe_time = time.process_time_ns() - t

            new_symbols = []

            if 'probing_done' in sm.stashes.keys():
                for s in sm.probing_done:
                    if s.monitor.probed_symbol is not None:
                        new_symbols.append(s.monitor.probed_symbol)

            for s in sm.deadended:
                if s.monitor.probing_pending:
                    s.monitor.collect_pending_probe()
                    if s.monitor.probed_symbol is not None:
                        new_symbols.append(s.monitor.probed_symbol)
            # print(new_symbols)
            self.probing_cache.insert(inputs, new_symbols)
            return True, [sym.__dict__ for sym in new_symbols], ms_time, 0, probe_time

        return False, None, ms_time, None, None

    def set_membership_hooks(self):
        if self.mode == 'membership':
            return
        logger.info('Setting hooks')
        for hook in self.hookers:
            hook.set_hook(self.project)
        self.mode = 'membership'


