#!/usr/bin/env python

import angr
import membership
import probe
import time


class QueryRunner:
    def __init__(self, file):
        self.file = file
        self.project = angr.Project(file, auto_load_libs=False)
        self.project.hook_symbol('strtoul', angr.SIM_PROCEDURES['libc']['strtol']())
        # self.project.hook_symbol('strlen', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
        self.mode = None
        self.set_membership_hooks()

    def membership_step_by_step(self, inputs, alphabet):
        self.set_membership_hooks()
        entry_state = self.project.factory.entry_state(add_options=angr.options.unicorn)
        entry_state.unicorn.concretization_threshold_memory = 5
        entry_state.unicorn.concretization_threshold_registers = 5
        entry_state.unicorn.concretization_threshold_instruction = 5
        entry_state.register_plugin('monitor', membership.MonitorStatePlugin(inputs, alphabet))
        entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        sm = self.project.factory.simulation_manager(entry_state)
        sm.move('active', 'position_0')
        for i in range(len(inputs)):
            stash = "position_%d" % i
            next_stash = "position_%d" % (i + 1)

            def filter_func(state):
                return next_stash if state.monitor.position == i + 1 else stash

            sm.run(stash=stash, filter_func=filter_func)

            print("Done symbol %d with %d states" % (i, len(getattr(sm, next_stash))))

            sm.merge(stash=next_stash)

            print("After merge: %d" % len(getattr(sm, next_stash)))

        final_stash = "position_%d" % len(inputs)

        if final_stash in sm.stashes.keys() and len(getattr(sm, final_stash)) > 0:
            print('Membership is true - probing....')

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
            return True, new_symbols, 0, 0, probe_time

        return False, None, 0, None, None

    def run_membership_query(self, inputs, alphabet):
        self.set_membership_hooks()
        entry_state = self.project.factory.entry_state(add_options=angr.options.unicorn)
        entry_state.register_plugin('monitor', membership.MonitorStatePlugin(inputs, alphabet))
        entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        # entry_state.options.add(angr.options.LAZY_SOLVES)
        sm = self.project.factory.simulation_manager(entry_state)
        # sm.use_technique(angr.exploration_techniques.DFS())
        t = time.process_time_ns()

        stashing = lambda sl: 'membership_true' if sl.monitor.is_done_membership() else None
        ret = sm.run(until=lambda sm: 'membership_true' in sm.stashes.keys() and len(sm.membership_true) > 0,
                     filter_func=stashing)
        ms_time = time.process_time_ns() - t
        # sm.move(from_stash='deadended', to_stash='monitored', filter_func=lambda s: s.monitor.is_done())
        if 'membership_true' in sm.stashes.keys() and len(sm.membership_true) > 0:
            print('Membership is true - probing....')
            # sm.merge(stash='membership_true')
            t = time.process_time_ns()
            # Wait for all states to reach the end of the membership word
            if len(sm.active) > 0:
                sm.run(filter_func=stashing)
            pre_probe_time = time.process_time_ns() - t

            print('Done pre-probing....')
            t = time.process_time_ns()
            # Wait for all states to probe
            sm.run(stash='membership_true', filter_func=lambda sl: 'probing_done' if sl.monitor.done_probing else None)
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
            return True, new_symbols, ms_time, pre_probe_time, probe_time

        return False, None, ms_time, None, None

    def run_probe_query(self, prefix, alphabet):
        self.set_probe_hooks()
        entry_state = self.project.factory.entry_state()
        entry_state.register_plugin('probe', probe.ProbeStatePlugin(prefix, alphabet))
        sm = self.project.factory.simulation_manager(entry_state)
        sm.run(until=lambda simgr: all(map(lambda state: state.probe.is_done_prefix(), simgr.active)))
        sm.run(until=lambda simgr: all(map(lambda state: state.probe.done_probing, simgr.active)))

        new_symbols = []

        for s in sm.active:
            if s.probe.done_probing:
                if s.probe.probed_symbol is not None:
                    new_symbols.append(s.probe.probed_symbol)

        for s in sm.deadended:
            if s.probe.done_probing:
                if s.probe.probed_symbol is not None:
                    new_symbols.append(s.probe.probed_symbol)
            elif s.probe.probing_pending:
                s.probe.collect_pending_probe()
                if s.probe.probed_symbol is not None:
                    new_symbols.append(s.probe.probed_symbol)

        return new_symbols

    def set_membership_hooks(self):
        if self.mode == 'membership':
            return
        self.project.hook_symbol('smtp_write', membership.MonitorHook(mode='send'))
        self.project.hook_symbol('smtp_read_aux', membership.MonitorHook(mode='read'))
        self.mode = 'membership'

    def set_probe_hooks(self):
        if self.mode == 'probe':
            return
        self.project.hook_symbol('smtp_write', probe.ProbeHook(mode='send'))
        self.project.hook_symbol('smtp_read_aux', probe.ProbeHook(mode='read'))
        self.mode = 'probe'
