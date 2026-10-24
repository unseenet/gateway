"""Matrix ``formatted_body`` (HTML) -> Unseenet Markdown (UN-RFC 0031), for gateway#26.

Only what Unseenet Markdown has comes through: emphasis, code, links, quotes,
lists, headings and line breaks. No HTML is ever passed on - every tag is either
turned into Markdown or dropped with its text kept - and text is escaped so it
shows as it was written. The quoted reply that clients put in ``<mx-reply>`` is
left out, as the plain ``body``'s fallback is (``strip_reply_fallback``).

Pure functions, no I/O.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

LINK_SCHEMES = ("http://", "https://", "unseenet:", "mailto:")
_SPECIAL = re.compile(r"([\\`*_\[\]<>#|~])")
_BLANKS = re.compile(r"\n{3,}")
SKIP = {"mx-reply", "script", "style", "head", "title"}
BLOCKS = {"p", "div", "blockquote", "pre", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6",
          "table", "tr", "hr"}


def _escape(text: str) -> str:
    out = _SPECIAL.sub(r"\\\1", text)
    # a line that would start a list or a heading by itself
    out = re.sub(r"(?m)^(\s*)([+-])(\s)", r"\1\\\2\3", out)
    return re.sub(r"(?m)^(\s*\d+)\.(\s)", r"\1\\.\2", out)


class _ToMarkdown(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0                 # inside <mx-reply> and the like
        self.pre = 0
        self.code = 0
        self.quote = 0
        self.lists: list[list] = []   # ["ul"|"ol", next number]
        self.links: list[str | None] = []

    # --- helpers ---
    def _text(self, s: str) -> None:
        if s:
            self.out.append(s)

    def _newline(self, n: int = 1) -> None:
        text = "".join(self.out)
        have = len(text) - len(text.rstrip("\n"))
        if text and have < n:
            self.out.append("\n" * (n - have))
        if self.quote and not self.pre:
            self.out.append("> " * self.quote)

    # --- the parser ---
    def handle_starttag(self, tag, attrs):
        if tag in SKIP:
            self.skip += 1
            return
        if self.skip:
            return
        a = dict(attrs)
        if tag in ("b", "strong"):
            self._text("**")
        elif tag in ("i", "em"):
            self._text("*")
        elif tag in ("del", "s", "strike"):
            self._text("~~")
        elif tag == "code" and not self.pre:
            self.code += 1
            self._text("`")
        elif tag == "pre":
            self._newline(2)
            self.pre += 1
            self._text("```\n")
        elif tag == "br":
            self._text("  \n" + ("> " * self.quote if self.quote else ""))
        elif tag == "p" or tag == "div":
            self._newline(2)
        elif tag == "blockquote":
            self._newline(2)
            self.quote += 1
            self._text("> ")
        elif tag in ("ul", "ol"):
            self._newline(2 if not self.lists else 1)
            self.lists.append([tag, int(a.get("start") or 1) if tag == "ol" else 0])
        elif tag == "li":
            self._newline(1)
            indent = "   " * (len(self.lists) - 1)
            if self.lists and self.lists[-1][0] == "ol":
                self._text(f"{indent}{self.lists[-1][1]}. ")
                self.lists[-1][1] += 1
            else:
                self._text(f"{indent}- ")
        elif re.fullmatch(r"h[1-6]", tag):
            self._newline(2)
            self._text("#" * int(tag[1]) + " ")
        elif tag == "a":
            href = (a.get("href") or "").strip()
            ok = href.lower().startswith(LINK_SCHEMES) and " " not in href
            self.links.append(href if ok else None)
            if ok:
                self._text("[")
        elif tag == "hr":
            self._newline(2)
            self._text("---")
            self._newline(2)
        elif tag == "img":            # pictures come as m.image events, not inline
            alt = a.get("alt") or a.get("title") or ""
            if alt:
                self._text(_escape(alt))

    def handle_endtag(self, tag):
        if tag in SKIP:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip:
            return
        if tag in ("b", "strong"):
            self._text("**")
        elif tag in ("i", "em"):
            self._text("*")
        elif tag in ("del", "s", "strike"):
            self._text("~~")
        elif tag == "code" and not self.pre:
            self.code = max(0, self.code - 1)
            self._text("`")
        elif tag == "pre":
            self.pre = max(0, self.pre - 1)
            text = "".join(self.out)
            self._text(("" if text.endswith("\n") else "\n") + "```")
            self._newline(2)
        elif tag in ("p", "div") or re.fullmatch(r"h[1-6]", tag):
            self._newline(2)
        elif tag == "blockquote":
            self.quote = max(0, self.quote - 1)
            self._newline(2)
        elif tag in ("ul", "ol"):
            if self.lists:
                self.lists.pop()
            self._newline(2 if not self.lists else 1)
        elif tag == "a":
            href = self.links.pop() if self.links else None
            if href:
                self._text(f"]({href.replace(')', '%29')})")

    def handle_data(self, data):
        if self.skip:
            return
        if self.pre or self.code:
            self._text(data.replace("```", "``​`") if self.pre else data.replace("`", "'"))
            return
        text = re.sub(r"\s+", " ", data)
        if self.quote:
            text = text.replace("\n", "\n" + "> " * self.quote)
        self._text(_escape(text))


def to_markdown(html: str) -> str:
    """Matrix HTML as Unseenet Markdown; '' when nothing is left."""
    p = _ToMarkdown()
    p.feed(html)
    p.close()
    text = "".join(p.out)
    text = "\n".join(line.rstrip() if not line.endswith("  ") else line for line in text.split("\n"))
    return _BLANKS.sub("\n\n", text).strip("\n").strip() + ("\n" if text.strip() else "")
