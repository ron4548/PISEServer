#!/usr/bin/env python

import angr
import membership
import probe


class QueryRunner:
    def __init__(self, file):
        self.file = file
        self.project = angr.Project(file, auto_load_libs=False)
        self.mode = None
        self.set_membership_hooks()

    def run_membership_query(self, inputs):
        self.set_membership_hooks()
        entry_state = self.project.factory.entry_state()
        entry_state.register_plugin('monitor', membership.MonitorStatePlugin(inputs))
        sm = self.project.factory.simulation_manager(entry_state)
        # sm.use_technique(angr.exploration_techniques.DFS())
        ret = sm.run(until=lambda sm: any(map(lambda state: state.monitor.is_done(), sm.active + sm.deadended)))
        # sm.move(from_stash='deadended', to_stash='monitored', filter_func=lambda s: s.monitor.is_done())
        if any(map(lambda state: state.monitor.is_done(), sm.active + sm.deadended)):
            return b'True'

        return b'False'

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



