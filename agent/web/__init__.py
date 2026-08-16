"""HTTP and WebSocket delivery: dashboard pages, the REST API, and live updates.

Nothing here holds reasoning or lifecycle logic -- pages call into `agent.runtime`.
Note `templatetags/` deliberately stays at the app root: Django only discovers
template tags in `<installed_app>/templatetags/`, and the installed app is `agent`.
"""
