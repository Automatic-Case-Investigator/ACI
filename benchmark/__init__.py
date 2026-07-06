"""ACI agent evaluation benchmark.

End-to-end suite that acquires a labelled attack dataset (AIT-LDS), preprocesses it,
loads it into Wazuh + TheHive, runs the agents against defined entry points, and
scores the runs against ground truth. Lives outside the offline `tests/` tree because
it needs live services (Wazuh, TheHive, LLM, AVFS) and emits metrics, not pass/fail.

See benchmark/README.md for the pipeline stages and how to run them.
"""
