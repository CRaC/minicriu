# minicriu

A proof-of-concept checkpoint/restore enginge implementation.

* Checkpoint is done by Linux kernel's built-in ability to dump core on a specific signal.
* Restore is done by `minicriu` that parses the core and lays out memory content as it was in the original process, then continues execution.

Test:
```
make run
```

Simulate checkpoint/restore:
```
make sim-run
```
