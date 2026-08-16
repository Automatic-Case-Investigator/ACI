"""HTTP views, grouped by the area of the product they serve.

Each sub-package holds every view for its area regardless of response type --
server-rendered pages and JSON API endpoints sit side by side, because they share
the same domain logic. Routing for all of them lives in one place: `web/urls.py`.
"""
