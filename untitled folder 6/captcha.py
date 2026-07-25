"""
captcha.py
Implements an image-based distorted-text CAPTCHA, generated server-side
with Pillow. The expected answer is kept only in the server-side session
(never embedded in the HTML/DOM), and is single-use: it is cleared the
moment it is checked, whether the check succeeds or fails, to prevent
replay against a stale image.

Rationale for this CAPTCHA type vs alternatives (expanded in the report):
text-distortion CAPTCHAs are well documented in the literature, do not
depend on a third-party service/API key, and clearly demonstrate the
underlying bot-mitigation principle for assessment purposes.
"""

import base64
import io
import os
import random
import string

from PIL import Image, ImageDraw, ImageFont, ImageFilter

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
CAPTCHA_LENGTH = 6
IMG_WIDTH, IMG_HEIGHT = 260, 90

# Characters that are visually unambiguous (no 0/O, 1/I/l confusion)
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _random_color(light_min=0, light_max=80):
    return tuple(random.randint(light_min, light_max) for _ in range(3))


def generate_captcha_text(length: int = CAPTCHA_LENGTH) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(length))


def generate_captcha_image(text: str) -> str:
    """Returns a base64-encoded PNG data URI of the distorted CAPTCHA text."""
    image = Image.new("RGB", (IMG_WIDTH, IMG_HEIGHT), color=(245, 247, 250))
    draw = ImageDraw.Draw(image)

    # Background noise: random lines
    for _ in range(8):
        x1, y1 = random.randint(0, IMG_WIDTH), random.randint(0, IMG_HEIGHT)
        x2, y2 = random.randint(0, IMG_WIDTH), random.randint(0, IMG_HEIGHT)
        draw.line((x1, y1, x2, y2), fill=_random_color(150, 210), width=2)

    # Draw each character with random rotation, size jitter and position
    font_size = 42
    try:
        font = ImageFont.truetype(FONT_PATH, font_size)
    except Exception:
        font = ImageFont.load_default()

    char_spacing = IMG_WIDTH // (len(text) + 1)
    for i, ch in enumerate(text):
        char_img = Image.new("RGBA", (60, 70), (0, 0, 0, 0))
        cdraw = ImageDraw.Draw(char_img)
        cdraw.text((10, 5), ch, font=font, fill=_random_color(0, 70))
        angle = random.randint(-30, 30)
        char_img = char_img.rotate(angle, expand=True, resample=Image.BICUBIC)

        x = char_spacing * (i + 1) - 25 + random.randint(-6, 6)
        y = random.randint(5, 20)
        image.paste(char_img, (x, y), char_img)

    # Foreground noise: random dots
    for _ in range(120):
        x, y = random.randint(0, IMG_WIDTH), random.randint(0, IMG_HEIGHT)
        draw.point((x, y), fill=_random_color(100, 180))

    image = image.filter(ImageFilter.SMOOTH)

    buf = io.BytesIO()
    image.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def new_captcha():
    """Returns (text, data_uri). Caller is responsible for storing `text`
    server-side (e.g. in the Flask session) and discarding it after use."""
    text = generate_captcha_text()
    data_uri = generate_captcha_image(text)
    return text, data_uri


def verify_captcha(submitted: str, expected: str) -> bool:
    if not submitted or not expected:
        return False
    return submitted.strip().upper() == expected.strip().upper()
