import json
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.notifications import tickets
from apps.notifications.consumers import NotificationConsumer
from apps.notifications.middleware import TicketAuthMiddleware
from apps.notifications.realtime import notification_group_name, notify_notification_created
from apps.notifications.views import WebSocketTicketView


class TicketStoreTests(SimpleTestCase):
    def test_ticket_is_stored_with_short_expiry_and_consumed_once(self):
        client = MagicMock()
        client.set.return_value = True
        user = SimpleNamespace(pk=42, tenant_id=7)

        with patch("apps.notifications.tickets._redis_client", return_value=client):
            ticket = tickets.issue_ticket(user, "https://app.example")
            client.eval.side_effect = [
                json.dumps({
                    "user_id": 42,
                    "tenant_id": 7,
                    "origin": "https://app.example",
                }),
                None,
            ]
            first_claims = tickets.consume_ticket(ticket)
            second_claims = tickets.consume_ticket(ticket)

        self.assertEqual(len(ticket), 43)
        self.assertEqual(client.set.call_args.kwargs["ex"], 30)
        self.assertTrue(client.set.call_args.kwargs["nx"])
        self.assertEqual(first_claims["user_id"], 42)
        self.assertIsNone(second_claims)

    def test_notification_groups_are_tenant_scoped(self):
        self.assertEqual(notification_group_name(7, 42), "notifications_7_42")
        self.assertEqual(notification_group_name(None, 42), "notifications_shared_42")

    def test_notification_publish_is_scheduled_after_commit(self):
        notification = SimpleNamespace(
            channel="in_app",
            recipient_id=42,
            recipient=SimpleNamespace(tenant_id=7),
            id=5,
            uid="notification-uid",
            subject="Subject",
            message="Message",
            status="sent",
            is_read=False,
            sent_at=None,
            created_at=MagicMock(isoformat=MagicMock(return_value="created-at")),
        )

        with patch("apps.notifications.realtime.transaction.on_commit") as on_commit:
            notify_notification_created(notification)

        self.assertEqual(on_commit.call_count, 1)
        with patch("apps.notifications.realtime._publish_notification") as publish:
            on_commit.call_args.args[0]()
        publish.assert_called_once()
        self.assertEqual(publish.call_args.args[0], "notifications_7_42")
        self.assertEqual(publish.call_args.args[1]["uid"], "notification-uid")


class WebSocketTicketViewTests(SimpleTestCase):
    def _request(self, origin="https://app.example"):
        from django.test import RequestFactory

        request = RequestFactory().post(
            "/notifications/ws-ticket/",
            HTTP_ORIGIN=origin,
        )
        request.user = SimpleNamespace(
            pk=42,
            tenant_id=7,
            tenant=SimpleNamespace(is_active=True),
            is_active=True,
            is_blocked=False,
            login_enabled=True,
            status="ACTIVE",
        )
        return request

    @override_settings(WS_ALLOWED_ORIGINS=["https://app.example"])
    def test_authenticated_eligible_user_receives_ticket(self):
        with patch("apps.notifications.views.issue_ticket", return_value="opaque"):
            response = WebSocketTicketView().post(self._request())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"ticket": "opaque", "expires_in": 30})
        self.assertEqual(response["Cache-Control"], "no-store")

    @override_settings(WS_ALLOWED_ORIGINS=["https://app.example"])
    def test_disallowed_origin_is_rejected(self):
        with patch("apps.notifications.views.issue_ticket") as issue:
            response = WebSocketTicketView().post(self._request("https://evil.example"))

        self.assertEqual(response.status_code, 403)
        issue.assert_not_called()


class WebSocketHandshakeTests(IsolatedAsyncioTestCase):
    async def test_ticket_authenticates_user_scope(self):
        user = SimpleNamespace(pk=42, id=42, tenant_id=7, is_authenticated=True)
        with override_settings(
            WS_ALLOWED_ORIGINS=["https://app.example"],
        ), patch(
            "apps.notifications.middleware._consume_ticket",
            new=AsyncMock(return_value={
                "user_id": 42,
                "tenant_id": 7,
                "origin": "https://app.example",
            }),
        ), patch(
            "apps.notifications.middleware._load_user",
            new=AsyncMock(return_value=user),
        ):
            received_scope = {}

            async def inner(scope, receive, send):
                received_scope.update(scope)

            app = TicketAuthMiddleware(inner)
            await app(
                {
                    "type": "websocket",
                    "query_string": b"ticket=opaque",
                    "headers": [(b"origin", b"https://app.example")],
                },
                None,
                AsyncMock(),
            )

            self.assertFalse(received_scope["ticket_auth_failed"])
            self.assertEqual(received_scope["tenant_id"], 7)
            self.assertIs(received_scope["user"], user)

    async def test_consumer_answers_ping(self):
        consumer = NotificationConsumer()
        consumer.send = AsyncMock()

        await consumer.receive('{"action": "ping"}')

        consumer.send.assert_awaited_once_with(
            text_data='{"type": "pong"}',
        )

    async def test_consumer_closes_unauthenticated_socket(self):
        consumer = NotificationConsumer()
        consumer.scope = {"ticket_auth_failed": True, "ticket_close_code": 4403}
        consumer.accept = AsyncMock()
        consumer.close = AsyncMock()

        await consumer.connect()

        consumer.accept.assert_awaited_once_with()
        consumer.close.assert_awaited_once_with(code=4403)

    async def test_wrong_origin_is_rejected(self):
        with override_settings(
            WS_ALLOWED_ORIGINS=["https://app.example"],
        ), patch(
            "apps.notifications.middleware._consume_ticket",
            new=AsyncMock(),
        ) as consume_ticket, patch(
            "apps.notifications.middleware._load_user",
            new=AsyncMock(),
        ) as load_user:
            received_scope = {}
            sent_events = []

            async def inner(scope, receive, send):
                received_scope.update(scope)
                await send({"type": "websocket.accept"})

            async def send(event):
                sent_events.append(event)

            app = TicketAuthMiddleware(inner)
            await app(
                {
                    "type": "websocket",
                    "query_string": b"ticket=opaque",
                    "headers": [(b"origin", b"https://evil.example")],
                },
                None,
                send,
            )

            self.assertTrue(received_scope["ticket_auth_failed"])
            self.assertEqual(received_scope["ticket_close_code"], 4403)
            self.assertEqual(sent_events, [{"type": "websocket.accept"}])
            self.assertTrue(received_scope["user"].is_anonymous)
            consume_ticket.assert_not_awaited()
            load_user.assert_not_awaited()
