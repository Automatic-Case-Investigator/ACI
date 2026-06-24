from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse

from agent.models import WorkflowTriggerConfig


class WorkflowTriggerSettingsTests(TestCase):
    def test_trigger_save_edit_and_delete(self):
        save_url = reverse("dashboard:settings_trigger_save")
        response = self.client.post(save_url, {
            "id": "thehive-case-webhook",
            "name": "TheHive case webhook",
            "provider_key": "thehive",
            "event_type": "new_case",
            "dedupe_window": "120",
            "secret": "first",
            "enabled": "1",
        })
        self.assertRedirects(response, reverse("dashboard:settings"))
        trigger = WorkflowTriggerConfig.objects.get(id="thehive-case-webhook")
        self.assertEqual(trigger.name, "TheHive case webhook")
        self.assertEqual(trigger.dedupe_window, 120)
        self.assertTrue(trigger.enabled)

        response = self.client.post(save_url, {
            "existing_id": "thehive-case-webhook",
            "name": "Renamed trigger",
            "provider_key": "thehive",
            "event_type": "new_case",
            "dedupe_window": "30",
            "secret": "",
        })
        self.assertRedirects(response, reverse("dashboard:settings"))
        trigger.refresh_from_db()
        self.assertEqual(trigger.name, "Renamed trigger")
        self.assertEqual(trigger.dedupe_window, 30)
        self.assertFalse(trigger.enabled)
        self.assertEqual(trigger.secret, "")

        response = self.client.post(reverse("dashboard:settings_trigger_delete"), {
            "id": "thehive-case-webhook",
        })
        self.assertRedirects(response, reverse("dashboard:settings"))
        self.assertFalse(WorkflowTriggerConfig.objects.filter(id="thehive-case-webhook").exists())

    def test_trigger_save_rejects_unregistered_event(self):
        response = self.client.post(reverse("dashboard:settings_trigger_save"), {
            "id": "bad-event",
            "name": "Bad event",
            "provider_key": "thehive",
            "event_type": "not_registered",
        })
        self.assertRedirects(response, reverse("dashboard:settings"))
        self.assertFalse(WorkflowTriggerConfig.objects.filter(id="bad-event").exists())

    def test_trigger_save_rejects_unsupported_provider(self):
        response = self.client.post(reverse("dashboard:settings_trigger_save"), {
            "id": "bad-provider",
            "name": "Bad provider",
            "provider_key": "aci-board",
            "event_type": "new_case",
        })
        self.assertRedirects(response, reverse("dashboard:settings"))
        self.assertFalse(WorkflowTriggerConfig.objects.filter(id="bad-provider").exists())

    def test_trigger_save_rejects_unsupported_provider_event(self):
        response = self.client.post(reverse("dashboard:settings_trigger_save"), {
            "id": "bad-provider-event",
            "name": "Bad provider event",
            "provider_key": "wazuh",
            "event_type": "new_case",
        })
        self.assertRedirects(response, reverse("dashboard:settings"))
        self.assertFalse(WorkflowTriggerConfig.objects.filter(id="bad-provider-event").exists())

    def test_settings_trigger_provider_options_are_not_mcp_providers(self):
        response = self.client.get(reverse("dashboard:settings"))
        options = response.context["trigger_provider_options"]
        self.assertEqual(
            [option["key"] for option in options],
            ["thehive", "wazuh"],
        )


@override_settings(WORKFLOWS_ENABLED=True)
class ConfiguredWebhookTests(TestCase):
    def _trigger(self, **overrides):
        values = {
            "id": "thehive-case-webhook",
            "name": "TheHive case webhook",
            "provider_key": "thehive",
            "event_type": "new_case",
            "enabled": True,
            "dedupe_window": 45,
            "secret": "",
        }
        values.update(overrides)
        return WorkflowTriggerConfig.objects.create(**values)

    def test_enabled_trigger_dispatches_registered_event(self):
        self._trigger(secret="s3cr3t")
        with patch("agent.views.webhooks._start_trigger_dispatch") as dispatch:
            response = self.client.post(
                reverse("configured_webhook", kwargs={"trigger_id": "thehive-case-webhook"}),
                data={
                    "objectType": "case",
                    "operation": "creation",
                    "object": {"_id": "~247152824"},
                },
                content_type="application/json",
                HTTP_X_ACI_WEBHOOK_SECRET="s3cr3t",
            )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["case_id"], "~247152824")
        dispatch.assert_called_once()
        trigger, case_id, body = dispatch.call_args.args
        self.assertEqual(trigger.id, "thehive-case-webhook")
        self.assertEqual(case_id, "~247152824")
        self.assertEqual(body["objectType"], "case")

    def test_disabled_trigger_does_not_dispatch(self):
        self._trigger(enabled=False)
        with patch("agent.views.webhooks._start_trigger_dispatch") as dispatch:
            response = self.client.post(
                reverse("configured_webhook", kwargs={"trigger_id": "thehive-case-webhook"}),
                data={"objectType": "case", "object": {"id": "case-1"}},
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ignored"])
        dispatch.assert_not_called()

    def test_secret_configured_requires_matching_secret(self):
        self._trigger(secret="expected")
        with patch("agent.views.webhooks._start_trigger_dispatch") as dispatch:
            response = self.client.post(
                reverse("configured_webhook", kwargs={"trigger_id": "thehive-case-webhook"}),
                data={"objectType": "case", "object": {"id": "case-1"}},
                content_type="application/json",
                HTTP_X_ACI_WEBHOOK_SECRET="wrong",
            )
        self.assertEqual(response.status_code, 403)
        dispatch.assert_not_called()

    def test_blank_secret_allows_request(self):
        self._trigger(secret="")
        with patch("agent.views.webhooks._start_trigger_dispatch") as dispatch:
            response = self.client.post(
                reverse("configured_webhook", kwargs={"trigger_id": "thehive-case-webhook"}),
                data={"objectType": "case", "object": {"id": "case-1"}},
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 202)
        dispatch.assert_called_once()

    def test_unknown_trigger_returns_404(self):
        response = self.client.post(
            reverse("configured_webhook", kwargs={"trigger_id": "missing"}),
            data={},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)

    def test_unregistered_event_is_ignored(self):
        self._trigger(event_type="missing_event")
        with patch("agent.views.webhooks._start_trigger_dispatch") as dispatch:
            response = self.client.post(
                reverse("configured_webhook", kwargs={"trigger_id": "thehive-case-webhook"}),
                data={"objectType": "case", "object": {"id": "case-1"}},
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ignored"])
        dispatch.assert_not_called()

    def test_thehive_compatibility_endpoint_uses_matching_trigger(self):
        self._trigger(id="compat-thehive", event_type="new_case")
        with patch("agent.views.webhooks._start_trigger_dispatch") as dispatch:
            response = self.client.post(
                reverse("thehive_webhook"),
                data={
                    "objectType": "case",
                    "operation": "creation",
                    "object": {"_id": "~case"},
                },
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 202)
        dispatch.assert_called_once()

    def test_wazuh_alert_trigger_dispatches_new_alert(self):
        WorkflowTriggerConfig.objects.create(
            id="wazuh-alert-webhook",
            name="Wazuh alert webhook",
            provider_key="wazuh",
            event_type="new_alert",
            enabled=True,
            dedupe_window=60,
        )
        with patch("agent.views.webhooks._start_trigger_dispatch") as dispatch:
            response = self.client.post(
                reverse("configured_webhook", kwargs={"trigger_id": "wazuh-alert-webhook"}),
                data={"id": "alert-42", "rule": {"id": "100001"}},
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["event_type"], "new_alert")
        dispatch.assert_called_once()

    def test_legacy_aci_prefixed_provider_key_still_dispatches(self):
        self._trigger(provider_key="aci-thehive")
        with patch("agent.views.webhooks._start_trigger_dispatch") as dispatch:
            response = self.client.post(
                reverse("configured_webhook", kwargs={"trigger_id": "thehive-case-webhook"}),
                data={"objectType": "case", "object": {"id": "case-legacy"}},
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 202)
        dispatch.assert_called_once()

    def test_unsupported_provider_runtime_is_ignored(self):
        self._trigger(provider_key="aci-board")
        with patch("agent.views.webhooks._start_trigger_dispatch") as dispatch:
            response = self.client.post(
                reverse("configured_webhook", kwargs={"trigger_id": "thehive-case-webhook"}),
                data={"id": "case-1"},
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ignored"])
        self.assertIn("unsupported trigger provider", response.json()["reason"])
        dispatch.assert_not_called()
