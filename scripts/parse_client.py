#!/usr/bin/env python3
"""Minimal client for the Nemotron-3.5-Parse vLLM server (stdlib only).

  python3 scripts/parse_client.py page.png
  python3 scripts/parse_client.py page.png --url http://gpu-host:8000 --api-key XXX -o page.txt

Request parameters follow the model card's vLLM example.  The raw output
contains text, semantic classes and normalized bounding boxes; use the
postprocessing helpers shipped in the model repository (postprocessing.py /
the nemotron_parse package) to turn it into Markdown.
"""
import argparse
import base64
import json
import mimetypes
import sys
import urllib.request

DEFAULT_PROMPT = "<predict_bbox><predict_classes><output_markdown><predict_text_in_pic>"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--model", default="nemotron-parse")
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--prompt", default=DEFAULT_PROMPT)
    ap.add_argument("--max-tokens", type=int, default=8744)
    ap.add_argument("-o", "--output")
    args = ap.parse_args()

    mime = mimetypes.guess_type(args.image)[0] or "image/png"
    with open(args.image, "rb") as f:
        data_url = f"data:{mime};base64,{base64.b64encode(f.read()).decode()}"

    body = {
        "model": args.model,
        "messages": [{
            "role": "user",
            # Text first, then the image (same order as NVIDIA's client).
            "content": [
                {"type": "text", "text": args.prompt},
                {"type": "image_url", "image_url": {"url": data_url}},
            ],
        }],
        "temperature": 0.0,
        "max_tokens": args.max_tokens,
        "top_k": 1,
        "repetition_penalty": 1.1,
        "skip_special_tokens": False,
    }
    headers = {"Content-Type": "application/json"}
    if args.api_key:
        headers["Authorization"] = f"Bearer {args.api_key}"
    req = urllib.request.Request(f"{args.url.rstrip('/')}/v1/chat/completions",
                                 data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=600) as r:
        text = json.load(r)["choices"][0]["message"]["content"]

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
