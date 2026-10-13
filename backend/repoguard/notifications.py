"""Redis accelerates polling; failures never lose a durable database job."""

import time
from collections.abc import Callable
from typing import cast

import redis


def notify(url: str) -> bool:
    client = redis.Redis.from_url(url, socket_timeout=0.2, socket_connect_timeout=0.2)
    try:
        client.publish("repoguard:jobs", "wake")
        return True
    except redis.RedisError:
        return False
    finally:
        client.close()


class Wakeups:
    """Long-lived subscription with bounded reconnect and database polling fallback."""

    def __init__(self, url: str) -> None:
        self.client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=0.2)
        factory = cast(Callable[..., redis.client.PubSub], self.client.pubsub)
        self.subscriber = factory(ignore_subscribe_messages=True)
        self.subscribed = False

    def wait(self) -> None:
        try:
            if not self.subscribed:
                self.subscriber.subscribe("repoguard:jobs")
                self.subscribed = True
            self.subscriber.get_message(timeout=1)
        except redis.RedisError:
            self.subscribed = False
            time.sleep(1)

    def close(self) -> None:
        self.subscriber.close()
        self.client.close()
