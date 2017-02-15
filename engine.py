import select
import time

class Timer(object):
    def __init__(self, trigger_time, callback):
        self.trigger_time = int(trigger_time)
        self.callback = callback

    @property
    def time_left(self):
        return max(0, self.trigger_time - int(time.time()))

    def trigger(self, engine):
        self.callback()

class Timeout(Timer):
    def __init__(self, timeout, callback):
        Timer.__init__(self, time.time() + timeout, callback)

class Interval(Timer):
    def __init__(self, interval, callback):
        Timer.__init__(self, time.time() + interval, callback)
        self.interval = interval

    def trigger(self, engine):
        Timer.trigger(self, engine)
        self.trigger_time += self.interval
        engine.add_interval(self.interval, self.callback)


class Engine(object):
    def __init__(self):
        self.epoll = select.epoll()
        self.timers = []
        self.servers = {}

    def start(self):
        while True:
            timeout = -1
            if self.timers:
                timeout = min([timer.time_left for timer in self.timers])

            try:
                events = self.epoll.poll(timeout)
            except IOError as e:
                if e.errno == 4: continue

            for (fd, event) in events:
                self.servers[fd].handle_event(event)

            for timer in self.timers:
                if timer.time_left == 0:
                    self.timers.remove(timer)
                    timer.trigger(self)

    def register(self, server):
        self.servers[server.fileno()] = server
        self.epoll.register(server.fileno(), select.EPOLLIN)

    def add_timer(self, trigger_time, callback):
        self.timers.append(Timer(trigger_time, callback))

    def add_timeout(self, timeout, callback):
        self.timers.append(Timeout(timeout, callback))

    def add_interval(self, interval, callback):
        self.timers.append(Interval(interval, callback))
