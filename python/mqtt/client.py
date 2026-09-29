import json
import logging
import os
import time
import uuid
from typing import Any, Callable, Optional
import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)


class MQTTClient:
    def __init__(
        self,
        brokers: Optional[str] = None,
        client_id: Optional[str] = None,
    ):
        broker_config = brokers or os.getenv(
            "MQTT_BROKERS",
            "emqx-1:1883,emqx-2:1883,emqx-3:1883",
        )

        self.brokers = self._parse_brokers(broker_config)

        self.client_id = client_id or os.getenv(
            "MQTT_CLIENT_ID",
            f"cyber-response-{uuid.uuid4()}",
        )

        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=self.client_id,
            protocol=mqtt.MQTTv5,
        )

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_publish = self._on_publish
        self.client.on_message = self._on_message
        self._message_callback: Optional[Callable] = None
        self._connected = False
        self._current_broker_index = 0

    @staticmethod
    def _parse_brokers(value: str) -> list[tuple[str, int]]:
        brokers = []

        for item in value.split(","):
            item = item.strip()

            if not item:
                continue

            if ":" in item:
                host, port = item.rsplit(":", 1)
                brokers.append((host, int(port)))
            else:
                brokers.append((item, 1883))

        if not brokers:
            raise ValueError("No MQTT brokers configured")

        return brokers

    def _on_connect(
        self,
        client,
        userdata,
        flags,
        reason_code,
        properties,
    ):
        if reason_code == 0:
            self._connected = True
            logger.info("Connected to MQTT broker %s:%s", *self.brokers[self._current_broker_index])

        else:
            logger.error("MQTT connection failed: %s", reason_code)

    def _on_disconnect(
        self,
        client,
        userdata,
        disconnect_flags,
        reason_code,
        properties,
    ):
        self._connected = False
        logger.warning("Disconnected from MQTT broker: %s", reason_code)

    def _on_publish(
        self,
        client,
        userdata,
        mid,
        reason_code,
        properties,
    ):
        logger.debug("MQTT message published: mid=%s", mid)

    def _on_message(
        self,
        client,
        userdata,
        message,
    ):
        logger.info("MQTT message received topic=%s payload=%s", message.topic, message.payload.decode("utf-8", errors="replace"))

        if self._message_callback:
            self._message_callback(message)

    def connect(self):
        last_error = None

        for offset in range(len(self.brokers)):
            index = (self._current_broker_index + offset) % len(self.brokers)
            host, port = self.brokers[index]

            try:
                logger.info("Connecting to MQTT broker %s:%s", host, port)
                self.client.connect(host, port, keepalive=60)
                self._current_broker_index = index
                self.client.loop_start()

                # Wait briefly for CONNACK.
                deadline = time.time() + 5

                while not self._connected and time.time() < deadline:
                    time.sleep(0.05)

                if self._connected:
                    return

                raise RuntimeError(f"MQTT broker {host}:{port} did not accept connection")

            except Exception as exc:
                last_error = exc
                logger.warning("Unable to connect to MQTT broker %s:%s: %s", host, port, exc)

        raise RuntimeError("Unable to connect to any MQTT broker") from last_error

    def publish(
        self,
        topic: str,
        payload: Any,
        *,
        qos: int = 1,
        retain: bool = False,
    ):
        if not self._connected:
            raise RuntimeError("MQTT client is not connected")

        if not isinstance(payload, str):
            payload = json.dumps(payload, ensure_ascii=False)

        result = self.client.publish(
            topic,
            payload=payload,
            qos=qos,
            retain=retain,
        )

        result.wait_for_publish()

        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT publish failed: rc={result.rc}")

    def subscribe(
        self,
        topic: str,
        *,
        qos: int = 1,
        callback: Optional[Callable] = None,
    ):
        if not self._connected:
            raise RuntimeError("MQTT client is not connected")

        self._message_callback = callback

        result, mid = self.client.subscribe(
            topic,
            qos=qos,
        )

        if result != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT subscribe failed: rc={result}")

        logger.info("Subscribed to MQTT topic=%s qos=%s mid=%s", topic, qos, mid)

    def disconnect(self):
        if self._connected:
            self.client.disconnect()

        self.client.loop_stop()
        self._connected = False
