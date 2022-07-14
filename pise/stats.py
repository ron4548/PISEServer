class Statistics:
    def __init__(self):
        self.ms_time = 0
        self.probe_time = 0
        self.pre_probe_time = 0
        self.count_memberships = 0

    def print(self):
        print('Total memberships:\t%d' % self.count_memberships)
        print('Total memberships time:\t%d' % self.ms_time)
        print('Total pre probe time:\t%d' % self.pre_probe_time)
        print('Total probe time:\t%d' % self.probe_time)

    def add_membership_count(self, count):
        self.count_memberships += count

    def add_membership_time(self, time):
        self.ms_time += time

    def add_pre_probe_time(self, time):
        if time is not None:
            self.pre_probe_time += time

    def add_probe_time(self, time):
        if time is not None:
            self.probe_time += time
