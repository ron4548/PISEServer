#!/usr/bin/env python

import angr
import logging

import membership
import time

from cache import SimulationCache, ProbingCache

l = logging.getLogger('inference_server')


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
        l.info('Performing membership, step by step')
        l.debug('Query: %s' % inputs)
        if self.probing_cache.has_contradiction(inputs):
            l.info('Query Answered by cache, answer is false')
            return False, None, 0, None, None
        self.set_membership_hooks()
        cached_prefix, cached_states = self.cache.lookup(inputs)

        if cached_states is not None:
            l.info('Retrieved %d states from cache, covering prefix of %d' % (len(cached_states), cached_prefix))
            l.debug('States: %s' % cached_states)
            for s in cached_states:
                s.register_plugin('monitor', membership.MonitorStatePlugin(inputs, cached_prefix))

            sm = self.project.factory.simulation_manager(cached_states)
        else:
            l.info('No prefix exists in cache, starting from the beginning')
            entry_state = self.project.factory.entry_state(add_options=angr.options.unicorn)
            entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            entry_state.register_plugin('monitor', membership.MonitorStatePlugin(inputs))
            sm = self.project.factory.simulation_manager(entry_state)

        sm.move('active', 'position_%d' % cached_prefix)
        # sm.use_technique(angr.exploration_techniques.threading.Threading())
        for i in range(cached_prefix, len(inputs)):
            stash = "position_%d" % i
            next_stash = "position_%d" % (i + 1)

            def filter_func(state):
                return next_stash if state.monitor.position == i + 1 else stash

            sm.run(stash=stash, filter_func=filter_func)

            if next_stash in sm.stashes.keys():
                l.info("Done symbol %d with %d states" % (i, len(getattr(sm, next_stash))))
                self.cache.store(inputs[:(i+1)], getattr(sm, next_stash))

        final_stash = "position_%d" % len(inputs)

        if final_stash in sm.stashes.keys() and len(getattr(sm, final_stash)) > 0:
            l.info('Membership is true - probing')

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
            return True, new_symbols, 0, 0, probe_time

        return False, None, 0, None, None

    def set_membership_hooks(self):
        if self.mode == 'membership':
            return
        l.info('Setting hooks')
        for hook in self.hookers:
            hook.set_hook(self.project)
        self.mode = 'membership'


