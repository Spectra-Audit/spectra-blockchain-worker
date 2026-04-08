"""Executive summary generation system.

Architecturally separate from the code audit agent system in scout/.
Uses its own agents, knowledge base, and self-improvement loop.

Triggers:
- After run_full_audit() completes (first generation)
- After weekly _update_all_dynamic_data() (regeneration)
- After metrics refresh (Celery tasks in backend)
"""
