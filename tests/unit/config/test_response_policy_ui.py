"""The response-policy settings surface: grid shape, cell state, and the save diff.

The matrix is rendered as a verdict × subject grid rather than 12 flat rows, and
Every cell renders identically — the grid states what is configured and does not
editorialise about how it differs from the shipped defaults. A "revert to defaults"
button drops the stored rows so the code defaults apply again.
"""

from __future__ import annotations

import os
import sys
import unittest

project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")

import django

django.setup()

from django.test import TestCase as DjangoTestCase

from agent.models import ResponsePolicy
from agent.dashboard.settings_views.rows import _response_policy_rows
from agent.runtime.analysis.verdict import VERDICT_ORDER
from agent.runtime.response_policy import policy


class _CleanMatrix(DjangoTestCase):
    """Base: clear stored rows inside the per-test transaction.

    The suite runs against the dev database, which holds the operator's real saved
    policy. Deleting here is rolled back after each test; deleting outside a
    transaction would destroy live settings.
    """

    def setUp(self):
        ResponsePolicy.objects.all().delete()


def _cell(grid, verdict, subject):
    row = next(r for r in grid["rows"] if r["verdict"] == verdict)
    return next(c for c in row["cells"] if c["subject"] == subject)


class GridShapeTests(_CleanMatrix):
    def test_grid_is_policy_rows_by_subject_columns(self):
        grid = _response_policy_rows()
        self.assertEqual([r["verdict"] for r in grid["rows"]], list(policy.POLICY_ROWS))
        self.assertEqual(len(grid["subject_headers"]), len(policy.SUBJECT_ORDER))
        for row in grid["rows"]:
            self.assertEqual(len(row["cells"]), len(policy.SUBJECT_ORDER))

    def test_verdict_slugs_carry_human_labels(self):
        grid = _response_policy_rows()
        labels = {r["verdict"]: r["verdict_label"] for r in grid["rows"]}
        self.assertEqual(labels["tp"], "True positive")
        self.assertEqual(labels["needs_investigation"], "Needs investigation")
        self.assertEqual(labels[policy.FAILURE_FALLBACK], "Failure fallback")

    def test_no_raw_slug_is_rendered_in_the_grid(self):
        """Slugs are identifiers, not operator-facing vocabulary."""
        html = self.client.get("/dashboard/settings/").content.decode(
            "utf-8", "replace"
        )
        grid = html[html.index("rp-grid") :]
        grid = grid[: grid.index("</form>")]
        for slug in policy.POLICY_ROWS:
            self.assertNotIn(f">{slug}<", grid, slug)

    def test_the_save_message_names_rows_by_label(self):
        r = self.client.post(
            "/dashboard/settings/response-policy",
            {f"action_{policy.FAILURE_FALLBACK}__case": policy.INVESTIGATE},
            follow=True,
        )
        message = [str(m) for m in r.context["messages"]][-1]
        self.assertIn("Failure fallback", message)
        self.assertNotIn(policy.FAILURE_FALLBACK, message)

    def test_every_cell_renders_a_select_including_single_option_ones(self):
        # FP on an alert offers only "No action" — it still gets a control, so the
        # cell reads as a deliberate configuration rather than a broken row.
        grid = _response_policy_rows()
        for row in grid["rows"]:
            for cell in row["cells"]:
                self.assertTrue(cell["actions"], f"{row['verdict']}/{cell['subject']}")
        fp_alert = _cell(grid, "fp", policy.ALERT)
        self.assertEqual([a["value"] for a in fp_alert["actions"]], [policy.NONE])

    def test_every_cell_offers_only_its_own_menu(self):
        grid = _response_policy_rows()
        for row in grid["rows"]:
            for cell in row["cells"]:
                allowed = policy.allowed_actions(row["verdict"], cell["subject"])
                self.assertEqual([a["value"] for a in cell["actions"]], list(allowed))

    def test_each_select_has_an_accessible_name(self):
        grid = _response_policy_rows()
        for row in grid["rows"]:
            for cell in row["cells"]:
                self.assertIn(row["verdict_label"].lower(), cell["aria_label"].lower())
                self.assertIn(cell["subject_label"], cell["aria_label"])


class NoDefaultDiffDisplayTests(_CleanMatrix):
    """The grid must not signal which cells differ from the shipped defaults."""

    def test_cells_carry_no_diff_or_status_keys(self):
        ResponsePolicy.objects.create(
            verdict="tp", subject="case", action=policy.RESOLVE
        )
        grid = _response_policy_rows()
        self.assertNotIn("changed", grid)
        self.assertNotIn("editable", grid)
        for row in grid["rows"]:
            for cell in row["cells"]:
                for key in ("changed", "consequence", "pending_connector", "guarded"):
                    self.assertNotIn(key, cell, f"{row['verdict']}/{cell['subject']}")

    def test_the_rendered_grid_styles_every_cell_the_same(self):
        ResponsePolicy.objects.create(
            verdict="tp", subject="case", action=policy.RESOLVE
        )
        html = self.client.get("/dashboard/settings/").content.decode(
            "utf-8", "replace"
        )
        grid = html[html.index("rp-grid") :]
        grid = grid[: grid.index("</form>")]
        self.assertEqual(grid.count('class="rp-cell"'), len(policy.cells()))
        for stale in (
            "rp-cell-state",
            "rp-cell-compute",
            "rp-flag",
            "changed from defaults",
        ):
            self.assertNotIn(stale, grid, stale)


class MergedAlertSubjectTests(_CleanMatrix):
    """SOAR and SIEM alert rows were merged into one `alert` subject."""

    def test_a_legacy_alert_row_still_resolves(self):
        from agent.runtime.config.overrides import resolve_response_policy

        ResponsePolicy.objects.create(
            verdict="tp", subject="soar_alert", action=policy.PROMOTE_CASE
        )
        self.assertEqual(
            resolve_response_policy()[("tp", policy.ALERT)], policy.PROMOTE_CASE
        )

    def test_a_current_row_wins_over_a_legacy_one(self):
        from agent.runtime.config.overrides import resolve_response_policy

        ResponsePolicy.objects.create(
            verdict="tp", subject="siem_alert", action=policy.PROMOTE_CASE
        )
        ResponsePolicy.objects.create(verdict="tp", subject="alert", action=policy.NONE)
        self.assertEqual(resolve_response_policy()[("tp", policy.ALERT)], policy.NONE)

    def test_a_legacy_row_naming_a_retired_action_is_still_dropped(self):
        from agent.runtime.config.overrides import resolve_response_policy

        ResponsePolicy.objects.create(
            verdict="tp", subject="soar_alert", action="document_alert"
        )
        self.assertEqual(
            resolve_response_policy()[("tp", policy.ALERT)],
            policy.default_action("tp", policy.ALERT),
        )

    def test_the_grid_shows_one_alert_column(self):
        # Read the label rather than hardcode it, so wording changes are not breakages.
        alert_label = dict(ResponsePolicy.SUBJECT_CHOICES)[policy.ALERT]
        grid = _response_policy_rows()
        self.assertEqual(
            grid["subject_headers"],
            [dict(ResponsePolicy.SUBJECT_CHOICES)[policy.CASE], alert_label],
        )


class FailureFallbackRowTests(_CleanMatrix):
    """The failure row governs runs that produced nothing usable."""

    def test_it_is_the_last_row_and_is_labelled(self):
        grid = _response_policy_rows()
        last = grid["rows"][-1]
        self.assertEqual(last["verdict"], policy.FAILURE_FALLBACK)
        self.assertEqual(last["verdict_label"], "Failure fallback")
        self.assertTrue(last["is_fallback"])

    def test_no_state_changing_action_is_offerable(self):
        # A run that produced nothing has earned nothing; resolving or promoting off
        # the back of it would assert a conclusion that was never reached.
        for subject in policy.SUBJECT_ORDER:
            allowed = policy.allowed_actions(policy.FAILURE_FALLBACK, subject)
            self.assertNotIn(policy.RESOLVE, allowed)
            self.assertNotIn(policy.PROMOTE_CASE, allowed)

    def test_defaults_leave_a_trace_on_cases_and_stay_quiet_on_alerts(self):
        self.assertEqual(
            policy.default_action(policy.FAILURE_FALLBACK, policy.CASE), policy.DOCUMENT
        )
        self.assertEqual(
            policy.default_action(policy.FAILURE_FALLBACK, policy.ALERT), policy.NONE
        )

    def test_it_is_configurable_like_any_other_row(self):
        from agent.runtime.config.overrides import resolve_response_policy

        self.client.post(
            "/dashboard/settings/response-policy",
            {f"action_{policy.FAILURE_FALLBACK}__case": policy.INVESTIGATE},
        )
        self.assertEqual(
            resolve_response_policy()[(policy.FAILURE_FALLBACK, policy.CASE)],
            policy.INVESTIGATE,
        )


class RevertToDefaultsTests(_CleanMatrix):
    URL = "/dashboard/settings/response-policy/reset"

    def test_it_drops_stored_rows_so_the_code_defaults_apply(self):
        from agent.runtime.config.overrides import resolve_response_policy

        ResponsePolicy.objects.create(
            verdict="tp", subject="case", action=policy.RESOLVE
        )
        self.client.post(self.URL)
        self.assertEqual(ResponsePolicy.objects.count(), 0)
        # Deleting rather than rewriting means a later change to the shipped defaults
        # still reaches a reverted deployment.
        resolved = resolve_response_policy()
        for cell in policy.cells():
            self.assertEqual(resolved[cell], policy.default_action(*cell), cell)

    def test_reverting_an_untouched_policy_is_harmless(self):
        r = self.client.post(self.URL, follow=True)
        self.assertIn(
            "already at defaults", [str(m) for m in r.context["messages"]][-1]
        )

    def test_the_button_is_rendered_in_the_form(self):
        html = self.client.get("/dashboard/settings/").content.decode(
            "utf-8", "replace"
        )
        self.assertIn("Revert to defaults", html)
        self.assertIn("/dashboard/settings/response-policy/reset", html)


class SaveDiffTests(_CleanMatrix):
    URL = "/dashboard/settings/response-policy"

    def _messages(self, response):
        # Newest last: an unfollowed POST leaves its message queued for the next render.
        return [str(m) for m in response.context["messages"]]

    def _latest(self, response):
        return self._messages(response)[-1]

    def test_a_real_change_is_described(self):
        r = self.client.post(self.URL, {"action_tp__case": "resolve"}, follow=True)
        message = self._latest(r)
        case_label = dict(ResponsePolicy.SUBJECT_CHOICES)[policy.CASE]
        self.assertIn(f"True positive on {case_label}", message)
        self.assertIn("Document and resolve", message)

    def test_resubmitting_the_same_values_reports_no_change(self):
        self.client.post(self.URL, {"action_tp__case": "resolve"}, follow=True)
        r = self.client.post(self.URL, {"action_tp__case": "resolve"}, follow=True)
        self.assertIn("unchanged", self._latest(r).lower())

    def test_submitting_defaults_unchanged_reports_no_change(self):
        r = self.client.post(self.URL, {"action_tp__case": "document"}, follow=True)
        self.assertIn("unchanged", self._latest(r).lower())

    def test_a_value_outside_the_cell_menu_is_ignored(self):
        r = self.client.post(
            self.URL, {"action_needs_investigation__case": "resolve"}, follow=True
        )
        self.assertIn("unchanged", self._latest(r).lower())
        self.assertFalse(ResponsePolicy.objects.filter(action="resolve").exists())

    def test_long_change_sets_are_summarised(self):
        r = self.client.post(
            self.URL,
            {
                "action_tp__case": "resolve",
                "action_fp__case": "resolve",
                "action_inconclusive__case": "investigate",
                "action_needs_investigation__case": "document",
            },
            follow=True,
        )
        self.assertIn("and 1 more", self._latest(r))


if __name__ == "__main__":
    unittest.main()
