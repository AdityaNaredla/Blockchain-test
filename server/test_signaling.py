"""Test WebSocket signaling: two clients connect, exchange messages."""
import asyncio
import json
import websockets


async def alice():
    async with websockets.connect("ws://127.0.0.1:8765/ws/signal/alice") as ws:
        # Receive presence
        msg = json.loads(await ws.recv())
        print(f"Alice received: {msg}")
        assert msg["type"] == "presence"
        assert "alice" in msg["users"]

        # Wait for Bob to come online
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        print(f"Alice received: {msg}")
        assert "bob" in msg["users"]

        # Send a signaling offer to Bob
        await ws.send(json.dumps({
            "type": "offer",
            "to": "bob",
            "sdp": "v=0\no=alice 123 1 IN IP4 127.0.0.1\n..."
        }))
        print("Alice sent: offer to bob")

        # Wait for Bob's answer
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        print(f"Alice received: {msg}")
        assert msg["type"] == "answer"
        assert msg["from"] == "bob"

        print("Alice: signaling exchange complete")


async def bob():
    await asyncio.sleep(0.5)  # Let alice connect first
    async with websockets.connect("ws://127.0.0.1:8765/ws/signal/bob") as ws:
        # Receive presence
        msg = json.loads(await ws.recv())
        print(f"Bob   received: {msg}")
        assert msg["type"] == "presence"

        # Wait for Alice's offer
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        print(f"Bob   received: {msg}")
        assert msg["type"] == "offer"
        assert msg["from"] == "alice"

        # Send answer back
        await ws.send(json.dumps({
            "type": "answer",
            "to": "alice",
            "sdp": "v=0\no=bob 456 1 IN IP4 127.0.0.1\n..."
        }))
        print("Bob   sent: answer to alice")

        # Test ping/pong
        await ws.send(json.dumps({"type": "ping"}))
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        print(f"Bob   received: {msg}")
        assert msg["type"] == "pong"

        print("Bob: signaling exchange complete")


async def main():
    await asyncio.gather(alice(), bob())
    print("\n" + "=" * 50)
    print("WEBSOCKET SIGNALING TEST PASSED")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
