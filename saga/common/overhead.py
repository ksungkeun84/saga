import time

class Monitor:
    """
    Singleton class to monitor and time different overheads using start/stop mechanics.
    """
    _instance = None
    f_time = time.process_time

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._runs = {}  # run_id -> {"start": time, "elapsed": float}
        return cls._instance

    def start(self, run_id):
        """
        Starts (or restarts) the stopwatch for a given run ID.
        """
        now = Monitor.f_time()
        if run_id not in self._runs:
            self._runs[run_id] = {"start": now, "elapsed": 0.0}
        else:
            self._runs[run_id]["start"] = now  # restart

    def stop(self, run_id):
        """
        Stops the stopwatch and accumulates the elapsed time.
        """
        now = Monitor.f_time()
        run = self._runs.get(run_id)
        if not run or run.get("start") is None:
            raise ValueError(f"Cannot stop timer: run ID '{run_id}' was never started.")
        elapsed = now - run["start"]
        run["elapsed"] += elapsed
        run["start"] = None  # timer is stopped

    def elapsed(self, run_id):
        """
        Returns the total elapsed time for a run ID (even if still running).
        """
        run = self._runs.get(run_id)
        if not run:
            raise ValueError(f"No timing data for run ID: {run_id}")
        if run["start"] is not None:
            # Include current running time
            return run["elapsed"] + (Monitor.f_time() - run["start"])
        return run["elapsed"]

    def elapsed_all(self):
        """
        Returns a dictionary of all elapsed times.
        """
        return {rid: self.elapsed(rid) for rid in self._runs}

    def reset(self, run_id=None):
        """
        Resets the specified run ID, or all if None.
        """
        if run_id is None:
            self._runs.clear()
        else:
            self._runs.pop(run_id, None)
