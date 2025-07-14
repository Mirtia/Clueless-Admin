import time
from datetime import datetime

def syscall_timing_check(callable_syscall, iterations=100, *args, **kwargs):
    """
    Measures execution time (ns) of a syscall-like Python function.
    Args:
        callable_syscall: A Python function (e.g., os.stat, os.listdir).
        iterations: Number of repetitions.
        *args, **kwargs: Arguments for the callable_syscall.

    Returns a JSON with the following structure:
        {
            "timestamp": "2025-10-01T12:00:00",
            "data": {
                "mean_ns": ...,
                "max_ns": ...,
                "min_ns": ...,
                "iterations": ...,
            },
            "message": "Syscall timing measured successfully."
        }
    """ 
    times = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        callable_syscall(*args, **kwargs)
        end = time.perf_counter_ns()
        times.append(end - start)
    mean_ns = sum(times) / iterations if iterations > 0 else None
    max_ns = max(times) if times else None
    min_ns = min(times) if times else None

    return {
        "timestamp": datetime.now().isoformat(),
        "data": {
            "mean_ns": mean_ns,
            "max_ns": max_ns,
            "min_ns": min_ns,
            "iterations": iterations,
        },
        "message": "Syscall timing measured successfully."
    }