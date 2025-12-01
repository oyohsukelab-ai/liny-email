import hashlib
import hmac
import logging
import os
import re
import smtplib
import ssl
import time
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import quote

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, EmailStr

load_dotenv()

SMTP_HOST = os.environ["SMTP_HOST"]
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASS = os.environ["SMTP_PASS"]
MAIL_FROM = os.environ["MAIL_FROM"]
SIGNING_SECRET = os.environ["SIGNING_SECRET"].encode()

MSG_DIR = Path("messages").resolve()
MSG_DIR.mkdir(exist_ok=True)

SAFE_ID = re.compile(r"^[A-Za-z0-9._-]+$")

app = FastAPI(title="Link-to-Mail (txt version)")

# --- ロガー設定（Heroku では stdout に出ればOK） ---
# uvicorn/gunicorn 経由ならこのログがそのまま heroku logs に出る
logger = logging.getLogger("uvicorn.error")
# ローカルで直接 `python app.py` する場合などに備えて最低限の設定
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


def make_signature(to: str, msg_id: str, ts: int) -> str:
    payload = f"{to}|{msg_id}|{ts}".encode()
    return hmac.new(SIGNING_SECRET, payload, hashlib.sha256).hexdigest()


def verify_signature(
    to: str, msg_id: str, ts: int, sig: str, max_age_sec: int = 600
) -> None:
    now = int(time.time())
    if abs(now - ts) > max_age_sec:
        logger.warning(f"[SEND_EXPIRED] to={to} id={msg_id} ts={ts} now={now}")
        raise HTTPException(status_code=400, detail="link expired")
    expected = make_signature(to, msg_id, ts)
    if not hmac.compare_digest(expected, sig):
        logger.warning(f"[SEND_INVALID_SIG] to={to} id={msg_id} ts={ts}")
        raise HTTPException(status_code=400, detail="invalid signature")


def resolve_msg_path(msg_id: str) -> Path:
    if not SAFE_ID.match(msg_id):
        logger.warning(f"[INVALID_ID] id={msg_id}")
        raise HTTPException(status_code=400, detail="invalid id")
    filename = msg_id if msg_id.endswith(".txt") else f"{msg_id}.txt"
    p = (MSG_DIR / filename).resolve()
    if MSG_DIR not in p.parents:
        logger.warning(f"[INVALID_PATH] id={msg_id} path={p}")
        raise HTTPException(status_code=400, detail="invalid path")
    return p


def parse_subject_body(raw: str, fallback_subject: str) -> tuple[str, str]:
    lines = raw.splitlines()
    subject = fallback_subject
    body = raw

    if lines:
        first = lines[0].strip("\ufeff ").rstrip()
        if first.lower().startswith("subject:"):
            subject = first.split(":", 1)[1].strip() or fallback_subject
            body = "\n".join(lines[1:]).lstrip()
        elif first.startswith("# "):
            subject = first[2:].strip() or fallback_subject
            body = "\n".join(lines[1:]).lstrip()
    return subject, body


def load_message(msg_id: str) -> tuple[str, str]:
    p = resolve_msg_path(msg_id)
    if not p.exists():
        logger.warning(f"[MSG_NOT_FOUND] id={msg_id} path={p}")
        raise HTTPException(status_code=404, detail="message not found")
    try:
        raw = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raw = p.read_text(encoding="cp932")
    subject, body = parse_subject_body(raw, fallback_subject=p.stem)
    return subject, body


def send_email(to_addr: str, subject: str, body: str):
    msg = EmailMessage()
    msg["From"] = MAIL_FROM
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


class SignedLinkParams(BaseModel):
    to: EmailStr
    id: str
    ts: int
    sig: str
    url: str


@app.get("/_sign_and_send")
def sign_and_send(
    request: Request,
    to: EmailStr = Query(...),
    id: str = Query(...),
):
    ts = int(time.time())
    sig = make_signature(str(to), id, ts)

    base_url = str(request.base_url).rstrip("/")

    # /send に飛ばすためのURLを組み立て
    url = f"{base_url}/send?to={quote(str(to))}&id={quote(id)}&ts={ts}&sig={sig}"

    logger.info(f"[SIGN_AND_REDIRECT] to={to} id={id} ts={ts} redirect_to={url}")

    # 307 にしておくと GET → GET のまま /send に渡る
    return RedirectResponse(url=url, status_code=307)


@app.get("/send", response_class=HTMLResponse)
def send_page(
    request: Request,
    to: EmailStr = Query(...),
    id: str = Query(...),
    ts: int = Query(...),
    sig: str = Query(...),
):
    # まずは何もせず「送信中…」ページを返す
    # 実際の送信は JS が /send_actual を叩いて行う

    html = f"""
    <html>
        <head>
            <meta charset="utf-8">
            <title>送信中...</title>
        </head>
        <body>
            <h1 style="font-family: sans-serif;">📮 メール送信中です…</h1>

            <script>
                fetch("/send_actual?to={to}&id={id}&ts={ts}&sig={sig}")
                    .then(res => res.json())
                    .then(data => {{
                        document.body.innerHTML = "<h1 style='font-family: sans-serif;'>🎉 送信が完了しました！</h1>";
                    }})
                    .catch(err => {{
                        document.body.innerHTML = "<h1 style='color:red;font-family:sans-serif;'>❌ 送信に失敗しました</h1>";
                    }});
            </script>
        </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/send_actual")
def send_actual(
    request: Request,
    to: EmailStr = Query(...),
    id: str = Query(...),
    ts: int = Query(...),
    sig: str = Query(...),
):
    client_ip = request.client.host if request.client else "unknown"

    logger.info(f"[SEND_REQUEST] ip={client_ip} to={to} id={id} ts={ts}")

    # 署名検証
    verify_signature(str(to), id, ts, sig)

    # メッセージ読み込み
    subject, body = load_message(id)

    # メール送信
    try:
        send_email(str(to), subject, body)
    except Exception:
        logger.exception(
            f"[SEND_FAILED] ip={client_ip} to={to} id={id} subject={subject}"
        )
        raise HTTPException(status_code=500, detail="send failed")

    logger.info(f"[SEND_SUCCESS] ip={client_ip} to={to} id={id} subject={subject}")

    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))  # Render では PORT が入る
    uvicorn.run(
        "app:app",  # "appモジュールのapp変数"の意味
        host="0.0.0.0",  # ローカルじゃなくて全インターフェースにバインド
        port=port,
    )
