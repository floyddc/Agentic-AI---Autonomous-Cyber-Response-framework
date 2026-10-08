import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Callable, Optional
import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)
MessageCallback = Callable[[mqtt.MQTTMessage], None]

MQTT_DEFAULT_KEEPALIVE = 60
MQTT_CONNECT_TIMEOUT = 5
MQTT_RECONNECT_INITIAL_DELAY = 1
MQTT_RECONNECT_MAX_DELAY = 30

class MQTTClient:

    def __init__(
        self,
        brokers: Optional[str] = None,
        client_id: Optional[str] = None,
        *,
        keepalive: int = MQTT_DEFAULT_KEEPALIVE,
        connect_timeout: float = MQTT_CONNECT_TIMEOUT,
        reconnect_initial_delay: float = MQTT_RECONNECT_INITIAL_DELAY,
        reconnect_max_delay: float = MQTT_RECONNECT_MAX_DELAY,
        manual_ack: bool = False,
    ):
        broker_config = brokers or os.getenv(
            "MQTT_BROKERS",
            "emqx-1:1883,emqx-2:1883,emqx-3:1883",
        )

        self.brokers = self._parse_brokers(broker_config)
        if client_id is None:
            client_id = os.getenv("MQTT_CLIENT_ID")
        if not client_id:
            hostname = os.getenv("HOSTNAME", uuid.uuid4().hex)
            client_id = f"cyber-response-{hostname}"
        self.client_id = client_id
        self.keepalive = keepalive
        self.connect_timeout = connect_timeout
        self.reconnect_initial_delay = reconnect_initial_delay
        self.reconnect_max_delay = reconnect_max_delay
        self.manual_ack = manual_ack

        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=self.client_id,
            protocol=mqtt.MQTTv5,
        )
        if self.manual_ack:
            self.client.manual_ack_set(True)

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_publish = self._on_publish
        self.client.on_subscribe = self._on_subscribe
        self.client.on_message = self._on_message

        self._subscriptions: dict[str, tuple[int, Optional[MessageCallback]]] = {}
        self._connected = threading.Event()
        self._stop_event = threading.Event()
        self._state_lock = threading.RLock()
        self._publish_condition = threading.Condition()
        self._publish_reasons: dict[int, Any] = {}
        self._subscribe_condition = threading.Condition()
        self._subscribe_reasons: dict[int, list[Any]] = {}
        self._connect_lock = threading.Lock()
        self._current_broker_index = 0
        self._connected_broker: Optional[tuple[str, int]] = None
        self._loop_started = False
        self._reconnect_thread: Optional[threading.Thread] = None
        self._last_disconnect_reason: Optional[str] = None

    # BROKER ----------------------------------------------------------------------------------------------------------------------------------------------------------     
    @staticmethod
    def _parse_brokers(value: str) -> list[tuple[str, int]]:
        brokers: list[tuple[str, int]] = []

        for item in value.split(","):
            item = item.strip()

            if not item:
                continue

            if ":" in item:
                host, port = item.rsplit(":", 1)
                host = host.strip()
                port = port.strip()

                if not host:
                    raise ValueError(f"Invalid MQTT broker configuration: {item!r}")

                try:
                    port_number = int(port)
                except ValueError as exc:
                    raise ValueError(f"Invalid MQTT broker port: {item!r}") from exc

                if not 1 <= port_number <= 65535:
                    raise ValueError(f"Invalid MQTT broker port: {port_number}")

                brokers.append((host, port_number))

            else:
                brokers.append((item, 1883))

        if not brokers:
            raise ValueError("No MQTT brokers configured")

        return brokers


    # CALLBACKS ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def _on_connect(
        self,
        client,
        userdata,
        flags,
        reason_code,
        properties,
    ):
        if reason_code != 0:
            logger.error("MQTT connection failed: reason_code=%s", reason_code)
            return

        with self._state_lock:
            self._connected_broker = self.brokers[self._current_broker_index]
            broker = self._connected_broker

        self._last_disconnect_reason = None
        logger.info("Connected to MQTT broker %s:%s client_id=%s", broker[0], broker[1], self.client_id)
        # Restore subscriptions after a successful connection
        self._restore_subscriptions()
        self._connected.set()

    def _on_disconnect(
        self,
        client,
        userdata,
        disconnect_flags,
        reason_code,
        properties,
    ):
        self._connected.clear()
        self._last_disconnect_reason = str(reason_code)

        with self._state_lock:
            broker = self._connected_broker
            self._connected_broker = None

        logger.warning("Disconnected from MQTT broker %s reason=%s", broker if broker else "unknown", reason_code)

        if self._stop_event.is_set():
            return

        self._ensure_reconnect_thread()

    def _on_publish(
        self,
        client,
        userdata,
        mid,
        reason_code,
        properties,
    ):
        logger.info("MQTT publish acknowledged mid=%s reason=%s", mid, reason_code)

        reason_value = getattr(reason_code, "value", reason_code)
        with self._publish_condition:
            self._publish_reasons[mid] = reason_value
            self._publish_condition.notify_all()

        if reason_value != 0:
            logger.warning("MQTT publish failed: mid=%s reason=%s", mid, reason_code)
            return

        logger.debug("MQTT message published: mid=%s", mid)

    def _on_subscribe(
        self,
        client,
        userdata,
        mid,
        reason_code_list,
        properties,
    ):
        reason_codes = list(reason_code_list)
        with self._subscribe_condition:
            self._subscribe_reasons[mid] = reason_codes
            self._subscribe_condition.notify_all()

        logger.info("MQTT subscription acknowledged mid=%s reason_codes=%s", mid, reason_codes)

    def _on_message(
        self,
        client,
        userdata,
        message,
    ):
        logger.info("MQTT message received topic=%s qos=%s payload=%s", message.topic, message.qos, message.payload.decode("utf-8", errors="replace"))
        callback: Optional[MessageCallback] = None

        with self._state_lock:
            subscriptions = list(self._subscriptions.items())

        for subscription_topic, (_, registered_callback) in subscriptions:
            if registered_callback is None:
                continue

            match_topic = subscription_topic

            if subscription_topic.startswith("$share/"):
                parts = subscription_topic.split("/", 2)

                if len(parts) == 3:
                    match_topic = parts[2]

            if mqtt.topic_matches_sub(match_topic, message.topic):
                callback = registered_callback
                break

        if callback is None:
            logger.debug("No callback registered for MQTT topic=%s", message.topic)
            return

        try:
            callback(message)
            if self.manual_ack:
                result = client.ack(message.mid, message.qos)
                if result != mqtt.MQTT_ERR_SUCCESS:
                    logger.error(
                        "Unable to acknowledge MQTT message topic=%s mid=%s rc=%s",
                        message.topic,
                        message.mid,
                        result,
                    )
                    client.disconnect()

        except Exception:
            logger.exception(
                "MQTT message callback failed for topic=%s; message was not acknowledged",
                message.topic,
            )
            if self.manual_ack:
                client.disconnect()

    def _connect_to_broker(self, index: int) -> bool:
        host, port = self.brokers[index]

        with self._connect_lock:
            if self._connected.is_set():
                return True

            with self._state_lock:
                self._current_broker_index = index

            try:
                logger.info("🔗 Connecting to MQTT broker %s:%s", host, port)
                self.client.connect(host, port, keepalive=self.keepalive)

                if self._wait_until_connected(self.connect_timeout):
                    return True

                logger.warning("Broker %s:%s did not provide CONNACK within %.1fs", host, port, self.connect_timeout)

            except Exception:
                logger.exception("Unable to connect to MQTT broker %s:%s", host, port)

            self._connected.clear()
            return False


    # CONNECTION MANAGEMENT ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def connect(self) -> None:
        if self._stop_event.is_set():
            raise RuntimeError("MQTT client has been stopped and cannot reconnect")

        if self._connected.is_set():
            return

        self._ensure_loop_started()

        for offset in range(len(self.brokers)):
            index = (self._current_broker_index + offset) % len(self.brokers)

            if self._connect_to_broker(index):
                return

        raise RuntimeError("Unable to connect to any MQTT broker")

    def _ensure_loop_started(self) -> None:
        with self._state_lock:
            if self._loop_started:
                return

            self.client.loop_start()
            self._loop_started = True

            logger.debug("MQTT network loop started client_id=%s", self.client_id)

    def _wait_until_connected(self, timeout: float) -> bool:
        return self._connected.wait(timeout=timeout)


    # RECONNECTION / FAILOVER  ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def _ensure_reconnect_thread(self) -> None:
        with self._state_lock:
            if self._stop_event.is_set():
                return

            if (self._reconnect_thread is not None and self._reconnect_thread.is_alive()):
                return

            self._reconnect_thread = threading.Thread(
                target=self._reconnect_loop,
                name=f"mqtt-reconnect-{self.client_id}",
                daemon=True,
            )

            self._reconnect_thread.start()

    def _reconnect_loop(self) -> None:
        delay = self.reconnect_initial_delay

        logger.info("Starting MQTT reconnect loop client_id=%s", self.client_id)

        while not self._stop_event.is_set():

            if self._connected.is_set():
                return

            for offset in range(len(self.brokers)):

                if self._stop_event.is_set():
                    return

                index = (self._current_broker_index + 1 + offset) % len(self.brokers)
                host, port = self.brokers[index]

                if self._connect_to_broker(index):
                    logger.info("MQTT failover successful: %s:%s", host, port,)
                    return

            logger.warning("All MQTT brokers unavailable; retrying in %.1fs", delay)

            self._stop_event.wait(delay)
            delay = min(delay * 2, self.reconnect_max_delay)

        logger.info("MQTT reconnect loop stopped client_id=%s", self.client_id)


    # PUBLISH ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def publish(
        self,
        topic: str,
        payload: Any,
        *,
        qos: int = 1,
        retain: bool = False,
        timeout: float = 10,
    ) -> None:
        if not self._connected.is_set():
            raise RuntimeError("MQTT client is not connected")

        if not topic:
            raise ValueError("MQTT topic cannot be empty")

        if qos not in (0, 1, 2):
            raise ValueError(f"Invalid MQTT QoS: {qos}")

        if not isinstance(payload, str):
            payload = json.dumps(payload, ensure_ascii=False)

        result = self.client.publish(
            topic,
            payload=payload,
            qos=qos,
            retain=retain,
        )

        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT publish failed: rc={result.rc}")

        deadline = time.monotonic() + timeout
        try:
            result.wait_for_publish(timeout=timeout)

        except RuntimeError as exc:
            raise RuntimeError(f"MQTT publish timed out: topic={topic}") from exc

        with self._publish_condition:
            while result.mid not in self._publish_reasons:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(
                        f"MQTT publish acknowledgement timed out: topic={topic}"
                    )
                self._publish_condition.wait(timeout=remaining)
            reason_code = self._publish_reasons.pop(result.mid)

        if reason_code != 0:
            raise RuntimeError(
                f"MQTT publish rejected: topic={topic}, reason={reason_code}"
            )

        logger.debug("MQTT publish completed topic=%s qos=%s mid=%s", topic, qos, result.mid)


    # SUBSCRIBE ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def subscribe(
        self,
        topic: str,
        *,
        qos: int = 1,
        callback: Optional[MessageCallback] = None,
    ) -> None:
        if not topic:
            raise ValueError("MQTT topic cannot be empty")

        if qos not in (0, 1, 2):
            raise ValueError(f"Invalid MQTT QoS: {qos}")

        # Store subscription before subscribing.
        with self._state_lock:
            self._subscriptions[topic] = (qos, callback)

        if not self._connected.is_set():
            raise RuntimeError("MQTT client is not connected")

        self._subscribe_topic(topic, qos, wait_for_ack=True)

    def _subscribe_topic(
        self,
        topic: str,
        qos: int,
        *,
        wait_for_ack: bool = False,
    ) -> None:
        result, mid = self.client.subscribe(topic, qos=qos)

        if result != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT subscribe failed: "f"topic={topic}, rc={result}")

        if wait_for_ack:
            with self._subscribe_condition:
                acknowledged = self._subscribe_condition.wait_for(
                    lambda: mid in self._subscribe_reasons,
                    timeout=self.connect_timeout,
                )
                reason_codes = self._subscribe_reasons.pop(mid, [])

            if not acknowledged:
                raise TimeoutError(f"Timed out waiting for MQTT SUBACK: topic={topic}, mid={mid}")

            if not reason_codes or any(
                getattr(reason_code, "value", reason_code) >= 128
                for reason_code in reason_codes
            ):
                raise RuntimeError(f"MQTT subscription rejected: topic={topic}, reason_codes={reason_codes}")

        logger.info("Subscribed to MQTT topic=%s qos=%s mid=%s", topic, qos, mid)

    def _restore_subscriptions(self) -> None:
        with self._state_lock:
            subscriptions = list(self._subscriptions.items())

        if not subscriptions:
            return

        logger.info("Restoring %d MQTT subscriptions", len(subscriptions))

        for topic, (qos, _) in subscriptions:
            try:
                self._subscribe_topic(topic, qos)

            except Exception:
                logger.exception("Unable to restore MQTT subscription topic=%s", topic)


    # STATE ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    @property
    def connected_broker(self) -> Optional[tuple[str, int]]:
        with self._state_lock:
            return self._connected_broker


    # SHUTDOWN ----------------------------------------------------------------------------------------------------------------------------------------------------------    
    def disconnect(self) -> None:
        logger.info("Stopping MQTT client client_id=%s", self.client_id)
        self._stop_event.set()
        self._connected.clear()

        try:
            self.client.disconnect()
        except Exception:
            logger.exception("Error while disconnecting MQTT client")

        with self._state_lock:
            loop_started = self._loop_started
            reconnect_thread = self._reconnect_thread

        if reconnect_thread is not None:
            reconnect_thread.join(timeout=5)

        if loop_started:
            self.client.loop_stop()

        with self._state_lock:
            self._loop_started = False
            self._reconnect_thread = None
            self._connected_broker = None

        logger.info("MQTT client stopped client_id=%s", self.client_id,)