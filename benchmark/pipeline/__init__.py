"""Pipeline stages. Each module exposes a `run(...)` entrypoint, is independently
invokable (read from disk, write to disk), idempotent, and — for the load stages —
tears down by tag. The stages, in order:

    acquire -> preprocess -> load_wazuh -> load_thehive -> runner -> score -> report
"""
