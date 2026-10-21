#!/usr/bin/env python3
"""agent-guard: Claude Code PreToolUse hook that blocks destructive Bash commands.

Python 3 stdlib only. Reads hook JSON from stdin or runs CLI check mode.

Commands are parsed by a small hand-written bash lexer/parser (quotes, escapes,
$'...', $(...), backticks, ${...}, heredocs, here-strings, process
substitution, subshells, groups, if/for/while/until/case, functions). Anything
it cannot parse, that nests too deeply, or that is too large gets "ask".
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

HOOK_EVENT = "PreToolUse"
REASON_PREFIX = "agent-guard:"
_FAIL_SAFE_REASON = f"{REASON_PREFIX} malformed hook payload; defaulting to ask"
_INTERNAL_ERROR_REASON = f"{REASON_PREFIX} internal error while analyzing command; defaulting to ask"

MAX_COMMAND_BYTES = 64 * 1024
MAX_DEPTH = 24
MAX_CODE_LITERALS = 200


class ParseError(Exception):
    """The command uses syntax the parser does not understand."""


class GuardLimit(Exception):
    """Nesting/recursion limit reached."""


# ---------------------------------------------------------------------------
# Words and AST
# ---------------------------------------------------------------------------

_LIT, _VAR, _DYN, _SUB = 0, 1, 2, 3


class Word:
    """A shell word made of literal text and expansions."""

    __slots__ = ("parts", "nested", "start", "end", "quoted", "procsub", "_buf", "_bq")

    def __init__(self, start: int) -> None:
        self.parts: List[Tuple[int, str, bool]] = []
        self.nested: List[list] = []
        self.start = start
        self.end = start
        self.quoted = False
        self.procsub = False
        self._buf: List[str] = []
        self._bq = False

    def lit(self, text: str, quoted: bool) -> None:
        if not text:
            return
        if self._buf and self._bq != quoted:
            self._flush()
        self._bq = quoted
        self._buf.append(text)

    def add(self, kind: int, text: str) -> None:
        self._flush()
        self.parts.append((kind, text, False))

    def _flush(self) -> None:
        if self._buf:
            self.parts.append((_LIT, "".join(self._buf), self._bq))
            self._buf = []

    def finish(self, end: int) -> None:
        self._flush()
        self.end = end

    def plain(self) -> Optional[str]:
        if self.quoted or len(self.parts) != 1:
            return None
        kind, text, quoted = self.parts[0]
        return text if kind == _LIT and not quoted else None


class HereDoc:
    __slots__ = ("delim", "quoted", "strip", "body", "word")

    def __init__(self, delim: str, quoted: bool, strip: bool) -> None:
        self.delim = delim
        self.quoted = quoted
        self.strip = strip
        self.body = ""
        self.word: Optional[Word] = None


class Redir:
    __slots__ = ("op", "fd", "target", "heredoc", "start", "end")

    def __init__(self, op: str, fd: Optional[int], start: int) -> None:
        self.op = op
        self.fd = fd
        self.target: Optional[Word] = None
        self.heredoc: Optional[HereDoc] = None
        self.start = start
        self.end = start


class Simple:
    __slots__ = ("assigns", "words", "redirs", "start", "end", "src")

    def __init__(self, assigns, words, redirs, start, end, src) -> None:
        self.assigns: List[Word] = assigns
        self.words: List[Word] = words
        self.redirs: List[Redir] = redirs
        self.start = start
        self.end = end
        self.src = src


class Compound:
    __slots__ = ("kind", "bodies", "words", "redirs", "start", "end", "src")

    def __init__(self, kind, bodies, words, redirs, start, end, src) -> None:
        self.kind = kind
        self.bodies: List[list] = bodies
        self.words: List[Word] = words
        self.redirs: List[Redir] = redirs
        self.start = start
        self.end = end
        self.src = src


# Script = List[Pipeline]; Pipeline = List[Simple | Compound]

# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------

_META = frozenset(" \t\n;&|()<>")
_WORD_RUN = re.compile(r"[^ \t\n;&|()<>'\"\\$`]+")
_DQ_RUN = re.compile(r"[^\"\\$`]+")
_HD_RUN = re.compile(r"[^\\$`]+")
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_DIGITS_RE = re.compile(r"\d+")
_PARAM_SIMPLE_RE = re.compile(r"([#!]?)([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])")
_ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?(\+?)=")
_REDIR_OPS = ("&>>", "<<<", "<<-", "&>", ">>", ">|", ">&", "<&", "<>", "<<", "<", ">")
_CTRL_OPS = (";;&", ";;", ";&", "&&", "||", "|&", "((")
_ANSI_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
    "e": "\x1b", "E": "\x1b", "\\": "\\", "'": "'", '"': '"', "?": "?",
}


class Lexer:
    def __init__(self, text: str, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            raise GuardLimit()
        self.text = text
        self.n = len(text)
        self.pos = 0
        self.depth = depth
        self.pending: List[HereDoc] = []

    def enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise GuardLimit()

    def leave(self) -> None:
        self.depth -= 1

    # -- tokens ------------------------------------------------------------

    def next_token(self) -> Tuple[str, Any, int, int]:
        t, n = self.text, self.n
        p = self.pos
        while True:
            while p < n and t[p] in " \t":
                p += 1
            if p + 1 < n and t[p] == "\\" and t[p + 1] == "\n":
                p += 2
                continue
            if p < n and t[p] == "#":
                q = t.find("\n", p)
                p = n if q < 0 else q
            break
        self.pos = p
        if p >= n:
            if self.pending:
                self._read_heredocs()
            return ("EOF", None, p, p)
        c = t[p]
        if c == "\n":
            self.pos = p + 1
            if self.pending:
                self._read_heredocs()
            return ("OP", "\n", p, p + 1)
        if c in "<>" and p + 1 < n and t[p + 1] == "(":
            return self._word_token()
        if c in "<>" or t.startswith("&>", p):
            return self._redir(p, p, None)
        if c in ";&|()":
            for op in _CTRL_OPS:
                if t.startswith(op, p):
                    self.pos = p + len(op)
                    return ("OP", op, p, self.pos)
            self.pos = p + 1
            return ("OP", c, p, p + 1)
        if c.isdigit():
            m = _DIGITS_RE.match(t, p)
            e = m.end()
            if e < n and t[e] in "<>" and not (e + 1 < n and t[e + 1] == "("):
                return self._redir(p, e, int(m.group()))
        return self._word_token()

    def _word_token(self) -> Tuple[str, Any, int, int]:
        start = self.pos
        w = self._word()
        if w is None:
            raise ParseError(f"unexpected character {self.text[start]!r}")
        return ("W", w, start, w.end)

    def _skip_blanks(self) -> None:
        t, n = self.text, self.n
        while self.pos < n:
            if t[self.pos] in " \t":
                self.pos += 1
            elif t.startswith("\\\n", self.pos):
                self.pos += 2
            else:
                break

    def _redir(self, start: int, op_start: int, fd: Optional[int]) -> Tuple[str, Any, int, int]:
        t = self.text
        op = next(o for o in _REDIR_OPS if t.startswith(o, op_start))
        self.pos = op_start + len(op)
        r = Redir(op, fd, start)
        self._skip_blanks()
        w = self._word()
        if w is None:
            raise ParseError(f"missing target for redirection {op}")
        if op in ("<<", "<<-"):
            delim = "".join(text for _, text, _ in w.parts)
            quoted = w.quoted or any(q for _, _, q in w.parts)
            r.heredoc = HereDoc(delim, quoted, op == "<<-")
            self.pending.append(r.heredoc)
        else:
            r.target = w
        r.end = self.pos
        return ("R", r, start, self.pos)

    def _read_heredocs(self) -> None:
        t, n = self.text, self.n
        pending, self.pending = self.pending, []
        for hd in pending:
            lines: List[str] = []
            while self.pos < n:
                q = t.find("\n", self.pos)
                if q < 0:
                    line, self.pos = t[self.pos :], n
                else:
                    line, self.pos = t[self.pos : q], q + 1
                if hd.strip:
                    line = line.lstrip("\t")
                if line == hd.delim:
                    break
                lines.append(line)
            hd.body = "\n".join(lines) + ("\n" if lines else "")
            if not hd.quoted:
                sub = Lexer(hd.body, self.depth + 1)
                w = Word(0)
                sub._dq(w, None)
                w.finish(sub.pos)
                hd.word = w

    def read_arith(self) -> None:
        self._arith("))")

    # -- words -------------------------------------------------------------

    def _word(self) -> Optional[Word]:
        t, n = self.text, self.n
        p = self.pos
        if p >= n:
            return None
        w = Word(p)
        if t[p] in "<>" and p + 1 < n and t[p + 1] == "(":
            self.pos = p + 2
            w.nested.append(self._subparse())
            w.add(_SUB, t[p] + "(...)")
            w.procsub = True
            w.finish(self.pos)
            return w
        if t[p] in _META:
            return None
        while self.pos < n:
            p = self.pos
            c = t[p]
            if c in _META:
                if c == "(" and self._array_assign_ok(w):
                    self._array(w)
                    continue
                break
            m = _WORD_RUN.match(t, p)
            if m:
                w.lit(m.group(), False)
                self.pos = m.end()
                continue
            if c == "\\":
                if p + 1 < n:
                    if t[p + 1] != "\n":
                        w.lit(t[p + 1], True)
                    self.pos = p + 2
                else:
                    w.lit("\\", False)
                    self.pos = p + 1
                continue
            if c == "'":
                q = t.find("'", p + 1)
                if q < 0:
                    raise ParseError("unterminated single quote")
                w.quoted = True
                w.lit(t[p + 1 : q], True)
                self.pos = q + 1
                continue
            if c == '"':
                w.quoted = True
                self.pos = p + 1
                self._dq(w, '"')
                continue
            if c == "$":
                self._dollar(w, False)
                continue
            self._backtick(w, False)
        w.finish(self.pos)
        return w

    def _array_assign_ok(self, w: Word) -> bool:
        w._flush()
        if len(w.parts) != 1 or w.parts[0][0] != _LIT or w.parts[0][2]:
            return False
        m = _ASSIGN_RE.match(w.parts[0][1])
        return bool(m) and m.end() == len(w.parts[0][1])

    def _array(self, w: Word) -> None:
        t, n = self.text, self.n
        self.pos += 1
        while True:
            while self.pos < n and t[self.pos] in " \t\n":
                self.pos += 1
            if self.pos < n and t[self.pos] == "#":
                q = t.find("\n", self.pos)
                self.pos = n if q < 0 else q
                continue
            if self.pos >= n:
                raise ParseError("unterminated array assignment")
            if t[self.pos] == ")":
                self.pos += 1
                break
            elem = self._word()
            if elem is None:
                raise ParseError("bad array element")
            w.nested.extend(elem.nested)
        w.add(_DYN, "(...)")

    def _dq(self, w: Word, term: Optional[str]) -> None:
        t, n = self.text, self.n
        run_re = _DQ_RUN if term else _HD_RUN
        escapable = '$`"\\\n' if term else "$`\\\n"
        while self.pos < n:
            p = self.pos
            c = t[p]
            if term and c == term:
                self.pos = p + 1
                return
            m = run_re.match(t, p)
            if m:
                w.lit(m.group(), True)
                self.pos = m.end()
                continue
            if c == "\\":
                if p + 1 < n and t[p + 1] in escapable:
                    if t[p + 1] != "\n":
                        w.lit(t[p + 1], True)
                    self.pos = p + 2
                else:
                    w.lit("\\", True)
                    self.pos = p + 1
                continue
            if c == "$":
                self._dollar(w, True)
                continue
            self._backtick(w, True)
        if term:
            raise ParseError("unterminated double quote")

    def _dollar(self, w: Word, in_dq: bool) -> None:
        t, n = self.text, self.n
        p = self.pos
        nx = t[p + 1] if p + 1 < n else ""
        if nx == "(":
            if t.startswith("((", p + 1):
                self.pos = p + 3
                self._arith("))")
                w.add(_DYN, "$((...))")
                return
            self.pos = p + 2
            w.nested.append(self._subparse())
            w.add(_SUB, "$(...)")
            return
        if nx == "{":
            self.pos = p + 2
            self._param(w)
            return
        if nx == "[":
            self.pos = p + 2
            self._arith("]")
            w.add(_DYN, "$[...]")
            return
        if nx == "'" and not in_dq:
            self._ansi_c(w)
            return
        if nx == '"' and not in_dq:
            w.quoted = True
            self.pos = p + 2
            self._dq(w, '"')
            return
        m = _NAME_RE.match(t, p + 1)
        if m:
            w.add(_VAR, m.group())
            self.pos = m.end()
            return
        if nx and (nx.isdigit() or nx in "@*#?$!-"):
            w.add(_DYN, "$" + nx)
            self.pos = p + 2
            return
        w.lit("$", in_dq)
        self.pos = p + 1

    def _param(self, w: Word) -> None:
        t, n = self.text, self.n
        m = _PARAM_SIMPLE_RE.match(t, self.pos)
        if m and t.startswith("}", m.end()):
            prefix, name = m.groups()
            self.pos = m.end() + 1
            if not prefix and _NAME_RE.fullmatch(name):
                w.add(_VAR, name)
            else:
                w.add(_DYN, "${...}")
            return
        tmp = Word(self.pos)
        while self.pos < n:
            c = t[self.pos]
            if c == "}":
                self.pos += 1
                break
            if c == "\\":
                self.pos += 2
                continue
            if c == "'":
                q = t.find("'", self.pos + 1)
                if q < 0:
                    raise ParseError("unterminated single quote")
                self.pos = q + 1
                continue
            if c == '"':
                self.pos += 1
                self._dq(tmp, '"')
                continue
            if c == "$":
                self._dollar(tmp, True)
                continue
            if c == "`":
                self._backtick(tmp, True)
                continue
            self.pos += 1
        else:
            raise ParseError("unterminated ${...}")
        tmp.finish(self.pos)
        w.nested.extend(tmp.nested)
        w.add(_SUB if any(k == _SUB for k, _, _ in tmp.parts) else _DYN, "${...}")

    def _arith(self, close: str) -> None:
        t, n = self.text, self.n
        i = self.pos
        depth = 0
        while i < n:
            c = t[i]
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0 and close == "))":
                    if not t.startswith("))", i):
                        raise ParseError("bad arithmetic expression")
                    content, self.pos = t[self.pos : i], i + 2
                    break
                depth -= 1
            elif c == "]" and close == "]" and depth == 0:
                content, self.pos = t[self.pos : i], i + 1
                break
            i += 1
        else:
            raise ParseError("unterminated arithmetic expression")
        if "$(" in content or "`" in content:
            raise ParseError("command substitution inside arithmetic")

    def _ansi_c(self, w: Word) -> None:
        t, n = self.text, self.n
        i = self.pos + 2
        out: List[str] = []
        while i < n:
            c = t[i]
            if c == "'":
                break
            if c == "\\" and i + 1 < n:
                e = t[i + 1]
                if e in _ANSI_ESCAPES:
                    out.append(_ANSI_ESCAPES[e])
                    i += 2
                    continue
                m = None
                if e == "x":
                    m = re.compile(r"[0-9A-Fa-f]{1,2}").match(t, i + 2)
                elif e == "u":
                    m = re.compile(r"[0-9A-Fa-f]{1,4}").match(t, i + 2)
                elif e == "U":
                    m = re.compile(r"[0-9A-Fa-f]{1,8}").match(t, i + 2)
                if m:
                    try:
                        out.append(chr(int(m.group(), 16)))
                    except (ValueError, OverflowError):
                        pass
                    i = m.end()
                    continue
                m = re.compile(r"[0-7]{1,3}").match(t, i + 1)
                if m:
                    out.append(chr(int(m.group(), 8) & 0xFF))
                    i = m.end()
                    continue
                if e == "c" and i + 2 < n:
                    out.append(chr(ord(t[i + 2]) & 0x1F))
                    i += 3
                    continue
                out.append("\\" + e)
                i += 2
                continue
            out.append(c)
            i += 1
        else:
            raise ParseError("unterminated $'...'")
        w.quoted = True
        w.lit("".join(out), True)
        self.pos = i + 1

    def _backtick(self, w: Word, in_dq: bool) -> None:
        t, n = self.text, self.n
        i = self.pos + 1
        buf: List[str] = []
        escapable = '$`\\"' if in_dq else "$`\\"
        while i < n:
            c = t[i]
            if c == "\\" and i + 1 < n and t[i + 1] in escapable:
                buf.append(t[i + 1])
                i += 2
                continue
            if c == "`":
                break
            buf.append(c)
            i += 1
        else:
            raise ParseError("unterminated backtick")
        self.pos = i + 1
        w.nested.append(parse_script("".join(buf), self.depth + 1))
        w.add(_SUB, "`...`")

    def _subparse(self) -> list:
        self.enter()
        parser = Parser(self)
        script = parser.parse_list(stop_ops=(")",))
        tok = parser.next()
        if tok[0] != "OP" or tok[1] != ")":
            raise ParseError("unterminated $(...)")
        self.leave()
        return script


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_RESERVED = frozenset(
    {"then", "elif", "else", "fi", "do", "done", "esac", "}", "in", "]]"}
)


class Parser:
    def __init__(self, lexer: Lexer) -> None:
        self.lx = lexer
        self.buf: List[Tuple[str, Any, int, int]] = []
        self.last_end = 0

    def peek(self, k: int = 0) -> Tuple[str, Any, int, int]:
        while len(self.buf) <= k:
            self.buf.append(self.lx.next_token())
        return self.buf[k]

    def next(self) -> Tuple[str, Any, int, int]:
        tok = self.peek()
        del self.buf[0]
        if tok[0] != "EOF":
            self.last_end = tok[3]
        return tok

    @staticmethod
    def _plain(tok: Tuple[str, Any, int, int]) -> Optional[str]:
        return tok[1].plain() if tok[0] == "W" else None

    def _is_op(self, tok, *ops: str) -> bool:
        return tok[0] == "OP" and tok[1] in ops

    def _skip_nl(self) -> None:
        while self._is_op(self.peek(), "\n"):
            self.next()

    def _expect_word(self, word: str) -> None:
        if self._plain(self.next()) != word:
            raise ParseError(f"expected {word!r}")

    def _expect_op(self, op: str) -> None:
        if not self._is_op(self.next(), op):
            raise ParseError(f"expected {op!r}")

    def parse_list(self, stop_ops: Sequence[str] = (), stop_words: Sequence[str] = ()) -> list:
        items: list = []
        while True:
            tok = self.peek()
            if self._is_op(tok, "\n"):
                self.next()
                continue
            if tok[0] == "EOF" or self._is_op(tok, *stop_ops):
                break
            if stop_words and self._plain(tok) in stop_words:
                break
            items.extend(self.parse_and_or())
            tok = self.peek()
            if self._is_op(tok, ";", "&", "\n"):
                self.next()
                continue
            if tok[0] == "EOF" or self._is_op(tok, *stop_ops):
                break
            if stop_words and self._plain(tok) in stop_words:
                break
            raise ParseError(f"unexpected token {tok[1] if tok[0] == 'OP' else tok[0]!r}")
        return items

    def parse_and_or(self) -> list:
        pipelines = [self.parse_pipeline()]
        while self._is_op(self.peek(), "&&", "||"):
            self.next()
            self._skip_nl()
            pipelines.append(self.parse_pipeline())
        return pipelines

    def parse_pipeline(self) -> list:
        while True:
            w = self._plain(self.peek())
            if w == "!":
                self.next()
                continue
            if w == "time":
                self.next()
                if self._plain(self.peek()) == "-p":
                    self.next()
                continue
            break
        cmds = [self.parse_command()]
        while self._is_op(self.peek(), "|", "|&"):
            self.next()
            self._skip_nl()
            cmds.append(self.parse_command())
        return cmds

    def parse_command(self):
        tok = self.peek()
        if tok[0] == "OP":
            if tok[1] == "(":
                self.next()
                self.lx.enter()
                body = self.parse_list(stop_ops=(")",))
                self._expect_op(")")
                self.lx.leave()
                return self._compound("subshell", [body], [], tok[2])
            if tok[1] == "((":
                self.next()
                self.lx.read_arith()
                return self._compound("arith", [], [], tok[2])
            raise ParseError(f"unexpected {tok[1]!r}")
        if tok[0] == "W":
            w = self._plain(tok)
            handler = {
                "{": self._group,
                "if": self._if,
                "while": self._loop,
                "until": self._loop,
                "for": self._for,
                "select": self._for,
                "case": self._case,
                "function": self._function,
                "[[": self._cond,
            }.get(w or "")
            if handler:
                return handler()
            if w in _RESERVED:
                raise ParseError(f"unexpected reserved word {w!r}")
            if w == "coproc":
                raise ParseError("unsupported construct: coproc")
            if w is not None and self._is_op(self.peek(1), "("):
                if self._is_op(self.peek(2), ")"):
                    start = self.next()[2]
                    self.next()
                    self.next()
                    return self._funcbody(start)
                raise ParseError("unexpected '('")
            return self.parse_simple()
        if tok[0] == "R":
            return self.parse_simple()
        raise ParseError("unexpected end of input")

    def _compound(self, kind: str, bodies: list, words: list, start: int) -> Compound:
        redirs = []
        while self.peek()[0] == "R":
            redirs.append(self.next()[1])
        return Compound(kind, bodies, words, redirs, start, self.last_end, self.lx.text)

    def _group(self) -> Compound:
        start = self.next()[2]
        self.lx.enter()
        body = self.parse_list(stop_words=("}",))
        self._expect_word("}")
        self.lx.leave()
        return self._compound("group", [body], [], start)

    def _if(self) -> Compound:
        start = self.next()[2]
        self.lx.enter()
        bodies = [self.parse_list(stop_words=("then",))]
        self._expect_word("then")
        bodies.append(self.parse_list(stop_words=("elif", "else", "fi")))
        while True:
            w = self._plain(self.next())
            if w == "elif":
                bodies.append(self.parse_list(stop_words=("then",)))
                self._expect_word("then")
                bodies.append(self.parse_list(stop_words=("elif", "else", "fi")))
                continue
            if w == "else":
                bodies.append(self.parse_list(stop_words=("fi",)))
                self._expect_word("fi")
                break
            if w == "fi":
                break
            raise ParseError("expected 'fi'")
        self.lx.leave()
        return self._compound("if", bodies, [], start)

    def _loop(self) -> Compound:
        start = self.next()[2]
        self.lx.enter()
        cond = self.parse_list(stop_words=("do",))
        self._expect_word("do")
        body = self.parse_list(stop_words=("done",))
        self._expect_word("done")
        self.lx.leave()
        return self._compound("loop", [cond, body], [], start)

    def _for(self) -> Compound:
        start = self.next()[2]
        self.lx.enter()
        words: List[Word] = []
        tok = self.peek()
        if self._is_op(tok, "(("):
            self.next()
            self.lx.read_arith()
        else:
            if tok[0] != "W":
                raise ParseError("expected loop variable")
            self.next()
            self._skip_nl()
            if self._plain(self.peek()) == "in":
                self.next()
                while self.peek()[0] == "W":
                    words.append(self.next()[1])
        while self._is_op(self.peek(), ";", "\n"):
            self.next()
        w = self._plain(self.next())
        if w == "do":
            body = self.parse_list(stop_words=("done",))
            self._expect_word("done")
        elif w == "{":
            body = self.parse_list(stop_words=("}",))
            self._expect_word("}")
        else:
            raise ParseError("expected 'do'")
        self.lx.leave()
        return self._compound("for", [body], words, start)

    def _case(self) -> Compound:
        start = self.next()[2]
        self.lx.enter()
        tok = self.next()
        if tok[0] != "W":
            raise ParseError("expected case subject")
        words = [tok[1]]
        self._skip_nl()
        self._expect_word("in")
        bodies = []
        while True:
            self._skip_nl()
            tok = self.peek()
            if self._plain(tok) == "esac":
                self.next()
                break
            if tok[0] == "EOF":
                raise ParseError("unterminated case")
            if self._is_op(tok, "("):
                self.next()
            while True:
                tok = self.next()
                if tok[0] != "W":
                    raise ParseError("bad case pattern")
                words.append(tok[1])
                tok = self.next()
                if self._is_op(tok, "|"):
                    continue
                if self._is_op(tok, ")"):
                    break
                raise ParseError("bad case pattern")
            bodies.append(self.parse_list(stop_ops=(";;", ";&", ";;&"), stop_words=("esac",)))
            if self._is_op(self.peek(), ";;", ";&", ";;&"):
                self.next()
        self.lx.leave()
        return self._compound("case", bodies, words, start)

    def _function(self) -> Compound:
        start = self.next()[2]
        if self.next()[0] != "W":
            raise ParseError("expected function name")
        if self._is_op(self.peek(), "("):
            self.next()
            self._expect_op(")")
        return self._funcbody(start)

    def _funcbody(self, start: int) -> Compound:
        self._skip_nl()
        self.lx.enter()
        body = self.parse_command()
        self.lx.leave()
        if not isinstance(body, Compound):
            raise ParseError("bad function body")
        return Compound("function", [[[body]]], [], [], start, self.last_end, self.lx.text)

    def _cond(self) -> Compound:
        start = self.next()[2]
        words: List[Word] = []
        while True:
            tok = self.next()
            if tok[0] == "EOF":
                raise ParseError("unterminated [[")
            if tok[0] == "W":
                if self._plain(tok) == "]]":
                    break
                words.append(tok[1])
            elif tok[0] == "R":
                if tok[1].heredoc is not None:
                    raise ParseError("heredoc inside [[")
                words.append(tok[1].target)
            elif not self._is_op(tok, "&&", "||", "(", ")", "|", "\n"):
                raise ParseError("unexpected token in [[")
        return self._compound("cond", [], words, start)

    def parse_simple(self) -> Simple:
        assigns: List[Word] = []
        words: List[Word] = []
        redirs: List[Redir] = []
        start: Optional[int] = None
        while True:
            tok = self.peek()
            if tok[0] == "W":
                self.next()
                if start is None:
                    start = tok[2]
                if not words and _is_assignment(tok[1]):
                    assigns.append(tok[1])
                else:
                    words.append(tok[1])
            elif tok[0] == "R":
                self.next()
                if start is None:
                    start = tok[2]
                redirs.append(tok[1])
            else:
                break
        if start is None:
            raise ParseError("empty command")
        return Simple(assigns, words, redirs, start, self.last_end, self.lx.text)


def _is_assignment(word: Word) -> bool:
    if not word.parts or word.parts[0][0] != _LIT or word.parts[0][2]:
        return False
    return bool(_ASSIGN_RE.match(word.parts[0][1]))


def _split_assignment(word: Word) -> Tuple[str, Word, bool]:
    text = word.parts[0][1]
    m = _ASSIGN_RE.match(text)
    value = Word(word.start)
    rest = text[m.end() :]
    value.parts = ([(_LIT, rest, False)] if rest else []) + word.parts[1:]
    value.quoted = word.quoted
    return m.group(1), value, bool(m.group(2))


def parse_script(text: str, depth: int = 0) -> list:
    lexer = Lexer(text, depth)
    parser = Parser(lexer)
    script = parser.parse_list()
    tok = parser.next()
    if tok[0] != "EOF":
        raise ParseError(f"unexpected {tok[1]!r}")
    return script


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------


class Arg:
    """A word after variable resolution: s is the value (or shape if dynamic)."""

    __slots__ = ("s", "dyn", "sub", "procsub")

    def __init__(self, s: str, dyn: bool = False, sub: bool = False, procsub: bool = False) -> None:
        self.s = s
        self.dyn = dyn
        self.sub = sub
        self.procsub = procsub


def _arg(word: Word, shell_vars: Dict[str, str]) -> Arg:
    out: List[str] = []
    dyn = sub = False
    for kind, text, _ in word.parts:
        if kind == _LIT:
            out.append(text)
        elif kind == _VAR:
            if text in shell_vars:
                out.append(shell_vars[text])
            else:
                out.append("$" + text)
                dyn = True
        else:
            out.append(text)
            dyn = True
            sub = sub or kind == _SUB
    return Arg("".join(out), dyn, sub, word.procsub)


class Stdin:
    __slots__ = ("kind", "text", "path")

    def __init__(self, kind: str, text: Optional[str] = None, path: Optional[str] = None) -> None:
        self.kind = kind  # heredoc | herestring | pipe | file | procsub
        self.text = text
        self.path = path


class Ctx:
    def __init__(self, cwd: Optional[str]) -> None:
        self.findings: List[Tuple[str, str, Optional[str]]] = []
        self.vars: Dict[str, str] = {}
        self.aliases: Dict[str, str] = {}
        self.cwd = cwd
        self.segment: Optional[str] = None
        self.depth = 0

    def add(self, sev: str, msg: str) -> None:
        self.findings.append((sev, f"{REASON_PREFIX} {msg}", self.segment))


def _opt_one(args: Sequence[Arg], i: int, short_val: str, long_val: Sequence[str],
             short_opt: str, flags: Set[str], vals: Dict[str, List[str]]) -> int:
    """Consume one option token at args[i]; return the next index."""
    s = args[i].s
    n = len(args)
    if s.startswith("--"):
        if "=" in s:
            key, value = s.split("=", 1)
            flags.add(key)
            vals.setdefault(key, []).append(value)
            return i + 1
        flags.add(s)
        if s in long_val and i + 1 < n:
            vals.setdefault(s, []).append(args[i + 1].s)
            return i + 2
        return i + 1
    step = 1
    for k in range(1, len(s)):
        ch = s[k]
        key = "-" + ch
        flags.add(key)
        if ch in short_val:
            value = s[k + 1 :]
            if not value and i + 1 < n:
                value = args[i + 1].s
                step = 2
            vals.setdefault(key, []).append(value)
            break
        if ch in short_opt:
            vals.setdefault(key, []).append(s[k + 1 :])
            break
    return i + step


def _is_opt(a: Arg) -> bool:
    return not a.dyn and len(a.s) > 1 and a.s.startswith("-")


def _opts(args: Sequence[Arg], i: int, short_val: str = "", long_val: Sequence[str] = (),
          short_opt: str = "") -> Tuple[int, Set[str], Dict[str, List[str]]]:
    """Parse options up to the first positional (getopt with '+')."""
    flags: Set[str] = set()
    vals: Dict[str, List[str]] = {}
    while i < len(args):
        if args[i].s == "--" and not args[i].dyn:
            i += 1
            break
        if not _is_opt(args[i]):
            break
        i = _opt_one(args, i, short_val, long_val, short_opt, flags, vals)
    return i, flags, vals


def _opts_all(args: Sequence[Arg], i: int, short_val: str = "", long_val: Sequence[str] = (),
              short_opt: str = "") -> Tuple[List[Arg], Set[str], Dict[str, List[str]], List[Arg]]:
    """Parse options anywhere (GNU permute); return (positionals, flags, values, after '--')."""
    flags: Set[str] = set()
    vals: Dict[str, List[str]] = {}
    pos: List[Arg] = []
    tail: List[Arg] = []
    while i < len(args):
        a = args[i]
        if a.s == "--" and not a.dyn:
            tail = list(args[i + 1 :])
            break
        if not _is_opt(a):
            pos.append(a)
            i += 1
            continue
        i = _opt_one(args, i, short_val, long_val, short_opt, flags, vals)
    return pos, flags, vals, tail


def _short_chars(args: Sequence[Arg]) -> str:
    return "".join(a.s[1:] for a in args if _is_opt(a) and not a.s.startswith("--"))


def _cmd_name(s: str) -> str:
    return s.rsplit("/", 1)[-1].lower()


def _q(a: Arg) -> str:
    return a.s if a.dyn else shlex.quote(a.s)


# -- paths -----------------------------------------------------------------

_SYSTEM_DIRS = frozenset(
    {
        "bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64", "libx32", "media",
        "mnt", "opt", "proc", "root", "run", "sbin", "snap", "srv", "sys", "usr", "var",
        "Applications", "Library", "System", "Users", "Volumes", "private", "cores",
    }
)
_HOME_PREFIX_RE = re.compile(r"^(?:\$HOME|~[A-Za-z0-9._-]*)(/.*)?$")
_BLOCK_DEV_RE = re.compile(
    r"^/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|disk\d|rdisk\d|md\d|"
    r"dm-\d|mapper/|loop\d|nbd\d|sr\d)"
)
_SAFE_SINKS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero", "-"})
_TYPICAL_OUTPUT_EXT = (".log", ".txt", ".out")


def _root_like(path: str) -> bool:
    norm = posixpath.normpath("/" + path.lstrip("/")) if path else "/"
    return norm == "/" or (norm.count("/") == 1 and any(ch in norm for ch in "*?["))


def _is_critical_path(a: Arg) -> bool:
    s = a.s.strip()
    if not s:
        return False
    m = _HOME_PREFIX_RE.match(s)
    if m:
        return _root_like(m.group(1) or "")
    if not s.startswith("/"):
        return False
    norm = posixpath.normpath(re.sub("/+", "/", s))
    if _root_like(norm):
        return True
    parts = norm.strip("/").split("/")
    if len(parts) == 1 and parts[0] in _SYSTEM_DIRS:
        return True
    if len(parts) == 2 and parts[0] in ("home", "Users"):
        return True
    home = os.environ.get("HOME")
    return bool(home) and norm == posixpath.normpath(home)


def _tmp_roots() -> List[str]:
    roots = ["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/dev/shm"]
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir and os.path.isabs(tmpdir):
        roots.append(os.path.normpath(tmpdir))
    return roots


def _is_under(path: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root if root == "/" else root + "/")


def _risky_write(a: Arg, ctx: Ctx) -> Optional[str]:
    """Why writing (truncating) this path deserves a prompt, or None."""
    s = a.s
    if a.dyn:
        prefix = s.split("$", 1)[0]
        if prefix.startswith("/") and "/" in prefix[1:]:
            if any(_is_under(os.path.dirname(os.path.normpath(prefix + "x")), r) for r in _tmp_roots()):
                return None
        return "write to a path that depends on runtime expansion"
    path = os.path.expanduser(s) if s.startswith("~") else s
    if not os.path.isabs(path):
        if ctx.cwd is None:
            return None if path.endswith(_TYPICAL_OUTPUT_EXT) else "write with unknown working directory"
        path = os.path.join(ctx.cwd, path)
    path = os.path.normpath(path)
    if any(_is_under(path, r) for r in _tmp_roots()):
        return None
    if ctx.cwd is None or not _is_under(path, ctx.cwd):
        return "write outside the working directory"
    if os.path.islink(path):
        return "write through a symlink"
    if os.path.isfile(path) and not path.endswith(_TYPICAL_OUTPUT_EXT):
        return "overwrites an existing file"
    return None


def _check_write(a: Arg, ctx: Ctx, *, append: bool, trunc_only: bool, via: str) -> None:
    s = a.s
    if not a.dyn and (s in _SAFE_SINKS or s.startswith(("/dev/fd/", "/dev/pts/"))):
        return
    if not a.dyn and s.startswith("/dev/"):
        if _BLOCK_DEV_RE.match(s):
            ctx.add("critical", f"write to block device detected: {via} {s}")
        elif not append:
            ctx.add("warn", f"write to device detected: {via} {s}")
        return
    if append:
        return
    if trunc_only:
        ctx.add("warn", f"truncating redirection detected: {via} {s}")
        return
    why = _risky_write(a, ctx)
    if why:
        ctx.add("warn", f"redirect {why} detected: {via} {s}")


# ---------------------------------------------------------------------------
# Analyzer: walk the AST
# ---------------------------------------------------------------------------


def _analyze_text(text: str, ctx: Ctx, stdin: Optional[Stdin], *, strict: bool) -> None:
    """Parse and analyze nested shell code (bash -c, heredoc to a shell, ...)."""
    ctx.depth += 1
    try:
        if ctx.depth > MAX_DEPTH:
            raise GuardLimit()
        try:
            script = parse_script(text, ctx.depth)
        except ParseError as e:
            if strict:
                ctx.add("warn", f"could not parse nested shell code ({e}); defaulting to ask")
            return
        saved = ctx.segment
        _run_script(script, ctx, stdin)
        ctx.segment = saved
    finally:
        ctx.depth -= 1


def _run_script(script: list, ctx: Ctx, stdin: Optional[Stdin]) -> None:
    for pipeline in script:
        out: Optional[str] = None
        for idx, cmd in enumerate(pipeline):
            st = stdin if idx == 0 else Stdin("pipe", out)
            out = _literal_output(cmd, ctx) if idx + 1 < len(pipeline) else None
            _run_command(cmd, ctx, st)


def _nested(word: Optional[Word], ctx: Ctx) -> None:
    if word is None:
        return
    for script in word.nested:
        saved = ctx.segment
        _run_script(script, ctx, None)
        ctx.segment = saved


def _nested_redirs(redirs: List[Redir], ctx: Ctx) -> None:
    for r in redirs:
        _nested(r.target, ctx)
        if r.heredoc is not None:
            _nested(r.heredoc.word, ctx)


def _stdin_from(redirs: List[Redir], ctx: Ctx) -> Optional[Stdin]:
    st = None
    for r in redirs:
        if r.fd not in (None, 0):
            continue
        if r.heredoc is not None:
            st = Stdin("heredoc", r.heredoc.body)
        elif r.op == "<<<":
            st = Stdin("herestring", _arg(r.target, ctx.vars).s + "\n")
        elif r.op in ("<", "<>"):
            a = _arg(r.target, ctx.vars)
            st = Stdin("procsub" if a.procsub else "file", None, a.s)
        elif r.op == "<&":
            st = Stdin("file")
    return st


def _check_redirs(redirs: List[Redir], ctx: Ctx, trunc_only: bool) -> None:
    for r in redirs:
        if r.op not in (">", ">|", ">>", "&>", "&>>", ">&") or r.target is None:
            continue
        a = _arg(r.target, ctx.vars)
        if r.op == ">&" and not a.dyn and (a.s == "-" or a.s.isdigit()):
            continue
        if a.procsub:
            continue
        _check_write(a, ctx, append=r.op in (">>", "&>>"), trunc_only=trunc_only, via=r.op)


def _truncation_only(args: List[Arg]) -> bool:
    if not args:
        return True
    if any(a.dyn for a in args):
        return False
    name = _cmd_name(args[0].s)
    rest = [a.s for a in args[1:]]
    if name in (":", "true") and not rest:
        return True
    if name == "cat" and rest == ["/dev/null"]:
        return True
    if name == "echo" and rest and all(re.fullmatch(r"-[neE]*n[neE]*", x) for x in rest):
        return True
    return name == "printf" and rest == [""]


def _literal_output(cmd, ctx: Ctx) -> Optional[str]:
    """Best-effort stdout of echo/printf/cat-heredoc feeding a pipe."""
    if not isinstance(cmd, Simple) or not cmd.words:
        return None
    args = [_arg(w, ctx.vars) for w in cmd.words]
    if args[0].dyn:
        return None
    name = _cmd_name(args[0].s)
    rest = args[1:]
    if name == "echo":
        k = 0
        while k < len(rest) and re.fullmatch(r"-[neE]+", rest[k].s):
            k += 1
        return " ".join(a.s for a in rest[k:]) + "\n"
    if name == "printf":
        return " ".join(a.s for a in rest).replace("\\n", "\n")
    if name == "cat" and not rest:
        st = _stdin_from(cmd.redirs, ctx)
        if st is not None and st.kind in ("heredoc", "herestring"):
            return st.text
    return None


def _run_command(cmd, ctx: Ctx, stdin: Optional[Stdin]) -> None:
    if isinstance(cmd, Compound):
        for w in cmd.words:
            _nested(w, ctx)
        _nested_redirs(cmd.redirs, ctx)
        ctx.segment = cmd.src[cmd.start : cmd.end].strip()
        own = _stdin_from(cmd.redirs, ctx)
        _check_redirs(cmd.redirs, ctx, False)
        for body in cmd.bodies:
            _run_script(body, ctx, own or stdin)
        return

    for w in cmd.assigns:
        _nested(w, ctx)
    for w in cmd.words:
        _nested(w, ctx)
    _nested_redirs(cmd.redirs, ctx)
    ctx.segment = cmd.src[cmd.start : cmd.end].strip()
    for w in cmd.assigns:
        name, value, append = _split_assignment(w)
        a = _arg(value, ctx.vars)
        if append or a.dyn:
            ctx.vars.pop(name, None)
        else:
            ctx.vars[name] = a.s
    args = [_arg(w, ctx.vars) for w in cmd.words]
    own = _stdin_from(cmd.redirs, ctx)
    _check_redirs(cmd.redirs, ctx, _truncation_only(args))
    if args:
        _exec(args, ctx, own or stdin)


# ---------------------------------------------------------------------------
# Wrappers (commands that run another command)
# ---------------------------------------------------------------------------
# A wrapper returns: int (index of the wrapped command), None (runs nothing),
# ("script", text), ("argv", [Arg]) or ("shell",) for a shell reading stdin.

_SUDO_LONG = ("--user", "--group", "--host", "--prompt", "--close-from", "--role", "--type",
              "--other-user", "--chdir", "--chroot", "--command-timeout")


def _w_sudo(args, i, ctx, stdin):
    j, f, _ = _opts(args, i + 1, "ughpCrtUDRT", _SUDO_LONG)
    if f & {"-e", "--edit", "-l", "--list", "-V", "--version", "-v", "--validate", "-K",
            "--remove-timestamp"}:
        return None
    if j >= len(args):
        return ("shell",) if f & {"-s", "--shell", "-i", "--login"} else None
    return j


def _w_doas(args, i, ctx, stdin):
    j, f, _ = _opts(args, i + 1, "uC")
    if j >= len(args):
        return ("shell",) if "-s" in f else None
    return j


def _w_env(args, i, ctx, stdin):
    j, n = i + 1, len(args)
    while j < n:
        a = args[j]
        s = a.s
        if a.dyn:
            break
        if s == "--":
            j += 1
            break
        if s in ("-S", "--split-string"):
            return ("script", " ".join(x.s for x in args[j + 1 :])) if j + 1 < n else None
        if s.startswith("--split-string=") or (s.startswith("-S") and len(s) > 2):
            first = s.split("=", 1)[1] if s.startswith("--") else s[2:]
            return ("script", " ".join([first] + [x.s for x in args[j + 1 :]]))
        if s in ("-u", "--unset", "-C", "--chdir"):
            j += 2
            continue
        if s.startswith("-") or re.match(r"[A-Za-z_][A-Za-z0-9_]*=", s):
            j += 1
            continue
        break
    return j if j < n else None


def _w_command(args, i, ctx, stdin):
    j, f, _ = _opts(args, i + 1)
    if f & {"-v", "-V"} or j >= len(args):
        return None
    return j


def _w_next(args, i, ctx, stdin):
    return i + 1 if i + 1 < len(args) else None


def _opts_wrapper(short_val: str = "", long_val: Sequence[str] = (), short_opt: str = "",
                  skip: int = 0, no_cmd_flags: Sequence[str] = ()):
    def handler(args, i, ctx, stdin):
        j, f, _ = _opts(args, i + 1, short_val, long_val, short_opt)
        if f & set(no_cmd_flags):
            return None
        j += skip
        return j if j < len(args) else None

    return handler


def _w_watch(args, i, ctx, stdin):
    j, f, _ = _opts(args, i + 1, "nq", ("--interval", "--equexit"))
    if j >= len(args):
        return None
    if f & {"-x", "--exec"}:
        return j
    return ("script", " ".join(a.s for a in args[j:]))


def _w_flock(args, i, ctx, stdin):
    j, f, v = _opts(args, i + 1, "wEc", ("--timeout", "--wait", "--conflict-exit-code", "--command"))
    cmds = v.get("-c", []) + v.get("--command", [])
    if cmds:
        return ("script", cmds[-1])
    k = j + 1
    if k < len(args) and args[k].s in ("-c", "--command"):
        return ("script", args[k + 1].s) if k + 1 < len(args) else None
    return k if k < len(args) else None


def _w_chroot(args, i, ctx, stdin):
    j, _, _ = _opts(args, i + 1, "", ("--userspec", "--groups"))
    if j >= len(args):
        return None
    return j + 1 if j + 1 < len(args) else ("shell",)


def _w_su(args, i, ctx, stdin):
    pos, f, v, tail = _opts_all(
        args, i + 1, "cCsgGwu",
        ("--command", "--session-command", "--shell", "--group", "--supp-group",
         "--whitelist-environment", "--user"),
    )
    cmds = v.get("-c", []) + v.get("-C", []) + v.get("--command", []) + v.get("--session-command", [])
    if cmds:
        return ("script", cmds[-1])
    if _cmd_name(args[i].s) == "runuser" and f & {"-u", "--user"}:
        argv = tail or pos
        return ("argv", argv) if argv else None
    return ("shell",)


def _w_script(args, i, ctx, stdin):
    _, _, v, _ = _opts_all(
        args, i + 1, "cEoIOBT",
        ("--command", "--echo", "--output-limit", "--log-io", "--log-in", "--log-out",
         "--log-timing", "--logging-format"),
        short_opt="t",
    )
    cmds = v.get("-c", []) + v.get("--command", [])
    if cmds:
        return ("script", cmds[-1])
    return ("shell",)


def _w_ssh(args, i, ctx, stdin):
    j, n = i + 1, len(args)
    flags: Set[str] = set()
    vals: Dict[str, List[str]] = {}
    host = None
    while j < n:
        a = args[j]
        if a.s == "--" and not a.dyn:
            j += 1
            continue
        if _is_opt(a):
            j = _opt_one(args, j, "BbcDEeFIiJLlmOoPpQRSWw", (), "", flags, vals)
            continue
        if host is None:
            host = a
            j += 1
            continue
        break
    if host is None or "-N" in flags:
        return None
    if j >= n:
        return ("shell",)
    return ("script", " ".join(a.s for a in args[j:]))


def _w_parallel(args, i, ctx, stdin):
    j, f, _ = _opts(
        args, i + 1, "jSaInNLEdC",
        ("--jobs", "--sshlogin", "--arg-file", "--delimiter", "--colsep", "--tmpdir",
         "--results", "--joblog", "--timeout", "--delay", "--env", "--sshloginfile",
         "--workdir", "--wd", "--tag-string", "--rpl", "--load", "--memfree", "--retries",
         "--halt", "--max-args", "--max-lines"),
    )
    cmd: List[Arg] = []
    inputs: List[Arg] = []
    seen_sep = False
    for a in args[j:]:
        if a.s in (":::", "::::", ":::+", "::::+"):
            seen_sep = True
            continue
        (inputs if seen_sep else cmd).append(a)
    if cmd:
        return ("script", " ".join(a.s for a in cmd + inputs))
    for a in inputs:
        _analyze_text(a.s, ctx, None, strict=False)
    if not inputs and not f & {"-a", "--arg-file"}:
        return ("shell",)
    return None


def _w_taskset(args, i, ctx, stdin):
    j, f, _ = _opts(args, i + 1)
    if f & {"-p", "--pid"}:
        return None
    return j + 1 if j + 1 < len(args) else None


def _w_ionice(args, i, ctx, stdin):
    j, f, _ = _opts(args, i + 1, "cnpPu", ("--class", "--classdata", "--pid", "--pgid", "--uid"))
    if f & {"-p", "-P", "-u", "--pid", "--pgid", "--uid"}:
        return None
    return j if j < len(args) else None


_WRAPPERS = {
    "sudo": _w_sudo,
    "doas": _w_doas,
    "env": _w_env,
    "command": _w_command,
    "builtin": _w_next,
    "nohup": _w_next,
    "chronic": _w_next,
    "unbuffer": _w_next,
    "catchsegv": _w_next,
    "busybox": _w_next,
    "toybox": _w_next,
    "exec": _opts_wrapper("a"),
    "time": _opts_wrapper("fo", ("--format", "--output")),
    "timeout": _opts_wrapper("ks", ("--kill-after", "--signal"), skip=1),
    "nice": _opts_wrapper("n", ("--adjustment",)),
    "ionice": _w_ionice,
    "stdbuf": _opts_wrapper("ioe", ("--input", "--output", "--error")),
    "setsid": _opts_wrapper(),
    "caffeinate": _opts_wrapper("tw"),
    "strace": _opts_wrapper("abeEIoOpPsSuUX"),
    "ltrace": _opts_wrapper("aAeElnopsSuwxX"),
    "xargs": _opts_wrapper(
        "adEILnPs",
        ("--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars", "--max-lines"),
        short_opt="eil",
    ),
    "watch": _w_watch,
    "flock": _w_flock,
    "chroot": _w_chroot,
    "su": _w_su,
    "runuser": _w_su,
    "script": _w_script,
    "ssh": _w_ssh,
    "parallel": _w_parallel,
    "taskset": _w_taskset,
    "pkexec": _opts_wrapper("", ("--user",)),
    "nsenter": _opts_wrapper("tSG", ("--target", "--setuid", "--setgid")),
    "unshare": _opts_wrapper(),
    "prlimit": _opts_wrapper("p", ("--pid",)),
    "systemd-run": _opts_wrapper("upEHMs", ("--unit", "--property", "--setenv", "--host",
                                            "--machine", "--slice", "--description",
                                            "--uid", "--gid", "--nice", "--working-directory")),
    "firejail": _opts_wrapper(),
    "k3s": _w_next,
    "microk8s": _w_next,
}


def _exec(args: List[Arg], ctx: Ctx, stdin: Optional[Stdin]) -> None:
    i = 0
    while i < len(args):
        a = args[i]
        if a.dyn:
            kind = "command substitution" if a.sub else "variable expansion"
            ctx.add("warn", f"obfuscated command name detected ({kind} in {a.s!r})")
            return
        name = _cmd_name(a.s)
        if i == 0 and name in ctx.aliases:
            value = ctx.aliases.pop(name)
            try:
                text = " ".join([value] + [_q(x) for x in args[1:]])
                _analyze_text(text, ctx, stdin, strict=True)
            finally:
                ctx.aliases[name] = value
            return
        handler = _WRAPPERS.get(name)
        if handler is None:
            break
        r = handler(args, i, ctx, stdin)
        if r is None:
            return
        if isinstance(r, int):
            i = r
            continue
        if r[0] == "script":
            _analyze_text(r[1], ctx, stdin, strict=True)
        elif r[0] == "argv":
            _exec(r[1], ctx, stdin)
        else:
            _shell_stdin(stdin, ctx, name)
        return
    if i >= len(args):
        return
    name = _cmd_name(args[i].s)
    rest = args[i + 1 :]
    checker = _COMMANDS.get(name)
    if checker is not None:
        checker(name, rest, ctx, stdin)
    elif name.startswith("mkfs"):
        ctx.add("critical", f"mkfs detected: {name}")
    elif _interp_lang(name):
        _c_interp(name, rest, ctx, stdin)
    elif name.upper() in _SQL_START:
        _check_sql(" ".join(a.s for a in args[i:]), ctx)


# ---------------------------------------------------------------------------
# Command checks
# ---------------------------------------------------------------------------


def _shell_stdin(stdin: Optional[Stdin], ctx: Ctx, name: str = "shell") -> None:
    if stdin is None or stdin.kind == "file":
        return
    if stdin.kind in ("heredoc", "herestring"):
        _analyze_text(stdin.text or "", ctx, None, strict=True)
        return
    if stdin.kind == "pipe":
        ctx.add("warn", "pipeline into shell interpreter detected")
        if stdin.text:
            _analyze_text(stdin.text, ctx, None, strict=False)
        return
    ctx.add("warn", f"{name} reading commands from process substitution detected")


def _c_shell(name, rest, ctx, stdin):
    k, n = 0, len(rest)
    has_c = has_s = False
    while k < n:
        a = rest[k]
        s = a.s
        if a.dyn:
            break
        if s in ("-", "--"):
            k += 1
            has_s = has_s or s == "-"
            break
        if s.startswith("--"):
            if s in ("--rcfile", "--init-file"):
                k += 2
                continue
            if s == "--command":
                has_c = True
                k += 1
                break
            if s.startswith("--command="):
                rest = list(rest[:k]) + [Arg(s.split("=", 1)[1], a.dyn, a.sub)] + list(rest[k + 1 :])
                n = len(rest)
                has_c = True
                break
            k += 1
            continue
        if s[0] in "-+" and len(s) > 1:
            consume = 0
            for ch in s[1:]:
                if ch == "c":
                    has_c = True
                elif ch == "s":
                    has_s = True
                elif ch in "oO":
                    consume += 1
            k += 1 + consume
            continue
        break
    if has_c:
        if k >= n:
            return
        script = rest[k]
        if script.sub:
            ctx.add("warn", f"{name} -c with command substitution cannot be verified")
            return
        _analyze_text(script.s, ctx, stdin, strict=True)
        return
    if has_s or k >= n:
        _shell_stdin(stdin, ctx, name)
        return
    script_file = rest[k]
    if script_file.procsub:
        ctx.add("warn", f"{name} reading script from process substitution detected")
    elif script_file.s in ("/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"):
        _shell_stdin(stdin, ctx, name)


def _c_source(name, rest, ctx, stdin):
    if not rest:
        return
    a = rest[0]
    if a.procsub:
        ctx.add("warn", f"{name} of process substitution detected")
    elif a.dyn and a.sub:
        ctx.add("warn", f"{name} of command substitution detected")
    elif a.s in ("/dev/stdin", "/dev/fd/0", "/proc/self/fd/0", "-"):
        _shell_stdin(stdin, ctx, name)


def _c_eval(name, rest, ctx, stdin):
    ctx.add("warn", "eval execution detected")
    if rest:
        _analyze_text(" ".join(a.s for a in rest), ctx, stdin, strict=False)


def _c_alias(name, rest, ctx, stdin):
    for a in rest:
        if "=" in a.s and not a.dyn:
            key, value = a.s.split("=", 1)
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]*", key):
                ctx.aliases[key.lower()] = value.strip()


def _c_unalias(name, rest, ctx, stdin):
    for a in rest:
        ctx.aliases.pop(a.s.lower(), None)


def _c_declare(name, rest, ctx, stdin):
    for a in rest:
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)=", a.s)
        if not m:
            continue
        if a.dyn:
            ctx.vars.pop(m.group(1), None)
        else:
            ctx.vars[m.group(1)] = a.s[m.end() :]


def _c_unset(name, rest, ctx, stdin):
    for a in rest:
        ctx.vars.pop(a.s, None)


def _c_cd(name, rest, ctx, stdin):
    if name == "popd":
        ctx.cwd = None
        return
    pos = [a for a in rest if not _is_opt(a)]
    if not pos:
        ctx.cwd = os.path.expanduser("~") if name == "cd" else None
        return
    a = pos[0]
    if a.dyn or a.s == "-":
        ctx.cwd = None
        return
    path = os.path.expanduser(a.s)
    if os.path.isabs(path):
        ctx.cwd = os.path.normpath(path)
    elif ctx.cwd is not None:
        ctx.cwd = os.path.normpath(os.path.join(ctx.cwd, path))


def _c_rm(name, rest, ctx, stdin):
    flags: List[str] = []
    targets: List[Arg] = []
    end_opts = False
    for a in rest:
        if not end_opts and a.s == "--" and not a.dyn:
            end_opts = True
        elif not end_opts and _is_opt(a):
            flags.append(a.s)
        else:
            targets.append(a)
    recursive = any(
        f == "--recursive" or (not f.startswith("--") and ("r" in f[1:] or "R" in f[1:]))
        for f in flags
    )
    if not recursive:
        return
    full = ("rm " + " ".join(a.s for a in rest)).strip()
    if "--no-preserve-root" in flags or any(_is_critical_path(t) for t in targets):
        ctx.add("critical", f"blocked recursive rm on critical path: {full}")
    else:
        ctx.add("warn", f"recursive rm detected: {full}")


def _c_chmod(name, rest, ctx, stdin):
    recursive = any(a.s == "--recursive" for a in rest) or "R" in _short_chars(rest)
    if recursive and any(_is_critical_path(a) for a in rest if not _is_opt(a)):
        ctx.add("warn", f"{name} -R on critical path detected: {' '.join(a.s for a in rest)}")


def _c_mv(name, rest, ctx, stdin):
    pos, _, v, tail = _opts_all(rest, 0, "tS", ("--target-directory", "--suffix"))
    pos = pos + tail
    targets = v.get("-t", []) + v.get("--target-directory", [])
    if "/dev/null" in targets or (len(pos) >= 2 and pos[-1].s == "/dev/null"):
        ctx.add("warn", "mv to /dev/null detected")


def _c_cp(name, rest, ctx, stdin):
    pos, _, _, tail = _opts_all(rest, 0, "tS", ("--target-directory", "--suffix"))
    pos = pos + tail
    if len(pos) >= 2 and pos[0].s in ("/dev/null", "/dev/zero"):
        ctx.add("warn", f"cp {pos[0].s} over a file detected")


def _c_tee(name, rest, ctx, stdin):
    pos, f, _, tail = _opts_all(rest, 0, "", ("--output-error",))
    if stdin is not None and stdin.kind == "file" and stdin.path in ("/dev/null", "/dev/zero"):
        ctx.add("warn", f"tee from {stdin.path} truncates files")
        return
    append = bool(f & {"-a", "--append"})
    for a in pos + tail:
        _check_write(a, ctx, append=append, trunc_only=False, via="tee")


def _c_dd(name, rest, ctx, stdin):
    for a in rest:
        if not a.s.startswith("of="):
            continue
        target = a.s[3:]
        if not a.dyn and (target in _SAFE_SINKS or target.startswith(("/dev/fd/", "/dev/pts/"))):
            continue
        if target.startswith("/dev/"):
            if _BLOCK_DEV_RE.match(target):
                ctx.add("critical", f"dd of=/dev/ detected: {target}")
            else:
                ctx.add("warn", f"dd of=/dev/ detected: {target}")
        else:
            ctx.add("warn", f"dd overwriting a file detected: of={target}")


def _c_truncate(name, rest, ctx, stdin):
    if rest and rest[0].s.upper() == "TABLE":
        _check_sql(" ".join(["TRUNCATE"] + [a.s for a in rest]), ctx)
        return
    ctx.add("warn", "truncate command detected")


def _c_shred(name, rest, ctx, stdin):
    if any(_BLOCK_DEV_RE.match(a.s) for a in rest):
        ctx.add("critical", "shred on block device detected")
    else:
        ctx.add("warn", "shred detected")


def _c_mkfs(name, rest, ctx, stdin):
    ctx.add("critical", f"mkfs detected: {name}")


def _c_wipefs(name, rest, ctx, stdin):
    flags = {a.s for a in rest}
    if flags & {"--all", "--offset"} or any(ch in _short_chars(rest) for ch in "ao"):
        ctx.add("critical", "wipefs detected")


def _c_blkdiscard(name, rest, ctx, stdin):
    ctx.add("critical", f"{name} detected")


def _c_sgdisk(name, rest, ctx, stdin):
    flags = {a.s for a in rest}
    if flags & {"--zap-all", "--clear", "--zap"} or any(ch in _short_chars(rest) for ch in "Zoz"):
        ctx.add("critical", "sgdisk wipe detected")


def _c_find(name, rest, ctx, stdin):
    k, n = 0, len(rest)
    while k < n:
        s = rest[k].s
        if s == "-delete":
            ctx.add("warn", "find -delete detected")
        if s in ("-exec", "-execdir", "-ok", "-okdir"):
            inner: List[Arg] = []
            k += 1
            while k < n and rest[k].s not in (";", "+"):
                inner.append(rest[k])
                k += 1
            if inner:
                if _cmd_name(inner[0].s) in ("rm", "unlink", "shred"):
                    ctx.add("warn", f"find -exec {_cmd_name(inner[0].s)} detected")
                _exec(inner, ctx, None)
        k += 1


def _c_rsync(name, rest, ctx, stdin):
    for a in rest:
        if a.s.startswith("--delete") or a.s in ("--del", "--remove-source-files", "--remove-sent-files"):
            ctx.add("warn", f"rsync {a.s} detected")
            return


def _c_crontab(name, rest, ctx, stdin):
    if "r" in _short_chars(rest):
        ctx.add("warn", "crontab -r detected")


# -- git --------------------------------------------------------------------


def _parse_git_restore_scope(args: List[str]) -> Tuple[bool, bool]:
    """Return (has_pathspec, staged_only)."""
    has_staged = has_worktree = has_pathspec = False
    i = 0
    while i < len(args):
        tok = args[i]
        low = tok.lower()
        if tok == "--":
            has_pathspec = i + 1 < len(args)
            break
        short = tok[1:] if tok.startswith("-") and not tok.startswith("--") else ""
        if low == "--staged" or "S" in short:
            has_staged = True
        if low == "--worktree" or "W" in short:
            has_worktree = True
        if tok in ("-s", "--source", "--pathspec-from-file"):
            has_pathspec = has_pathspec or tok == "--pathspec-from-file"
            i += 2
            continue
        if low.startswith("--pathspec-from-file="):
            has_pathspec = True
        if tok.startswith("-") and tok != "-":
            i += 1
            continue
        has_pathspec = True
        i += 1
    return has_pathspec, has_staged and not has_worktree


def _git_push(sargs: List[Arg], ctx: Ctx) -> None:
    forced = lease = delete = mirror = prune = plus = False
    pos: List[str] = []
    k, n = 0, len(sargs)
    while k < n:
        s = sargs[k].s
        if s == "--":
            pos.extend(a.s for a in sargs[k + 1 :])
            break
        if s.startswith("--"):
            key = s.split("=", 1)[0]
            if key == "--force":
                forced = True
            elif key.startswith("--force-with-lease"):
                lease = True
            elif key == "--delete":
                delete = True
            elif key == "--mirror":
                mirror = True
            elif key == "--prune":
                prune = True
            elif key in ("--repo", "--receive-pack", "--exec", "--push-option") and "=" not in s:
                k += 1
        elif s.startswith("-") and len(s) > 1:
            for idx, ch in enumerate(s[1:], 1):
                if ch == "f":
                    forced = True
                elif ch == "d":
                    delete = True
                elif ch == "o":
                    if idx == len(s) - 1:
                        k += 1
                    break
        else:
            pos.append(s)
        k += 1
    for ref in pos[1:]:
        if ref.startswith("+") and len(ref) > 1:
            plus = True
        if ref.startswith(":") and len(ref) > 1:
            delete = True
    if lease:
        ctx.add("warn", "git push --force-with-lease requires confirmation")
    elif forced:
        ctx.add("warn", "git push --force detected")
    if plus:
        ctx.add("warn", "git push +refspec detected")
    if delete:
        ctx.add("warn", "git push branch deletion (--delete / :ref) detected")
    if mirror:
        ctx.add("warn", "git push --mirror detected")
    if prune:
        ctx.add("warn", "git push --prune detected")


def _c_git(name, rest, ctx, stdin):
    j, _, _ = _opts(rest, 0, "Cc", ("--git-dir", "--work-tree", "--namespace", "--super-prefix",
                                    "--config-env"))
    if j >= len(rest):
        return
    sub = rest[j].s.lower()
    sargs = list(rest[j + 1 :])
    ss = [a.s for a in sargs]
    short = _short_chars(sargs)
    longs = {s.split("=", 1)[0] for s in ss if s.startswith("--")}

    if sub == "push":
        _git_push(sargs, ctx)
    elif sub == "reset":
        if "--hard" in longs:
            ctx.add("warn", "git reset --hard detected")
    elif sub == "clean":
        dry = "n" in short or "--dry-run" in longs
        force = "f" in short or "--force" in longs
        if force and not dry:
            ctx.add("warn", "git clean -f detected (deletes untracked files)")
    elif sub == "branch":
        if "D" in short:
            ctx.add("warn", "git branch -D detected")
        elif ("d" in short or "--delete" in longs) and ("f" in short or "--force" in longs):
            ctx.add("warn", "git branch --delete --force detected")
    elif sub == "checkout":
        if "--" in ss:
            if ss.index("--") + 1 < len(ss):
                ctx.add("warn", "git checkout pathspec restore detected")
            return
        if "f" in short or "--force" in longs:
            ctx.add("warn", "git checkout --force detected")
        for s in ss:
            if s.startswith("-"):
                continue
            if s in (".", "..", "*") or s.startswith(("./", "../", ":/", ":(")) or "*" in s:
                ctx.add("warn", "git checkout pathspec restore detected")
                break
    elif sub == "restore":
        has_pathspec, staged_only = _parse_git_restore_scope(ss)
        if has_pathspec and not staged_only:
            ctx.add("warn", "git restore worktree pathspec detected")
    elif sub == "switch":
        if "f" in short or longs & {"--force", "--discard-changes"}:
            ctx.add("warn", "git switch --discard-changes detected")
    elif sub == "stash":
        if ss and ss[0].lower() in ("drop", "clear"):
            ctx.add("warn", f"git stash {ss[0].lower()} detected")
    elif sub in ("filter-branch", "filter-repo"):
        ctx.add("warn", f"git {sub} detected")
    elif sub == "reflog":
        if ss and ss[0] in ("expire", "delete"):
            ctx.add("warn", f"git reflog {ss[0]} detected")
    elif sub == "gc":
        if any(s in ("--prune=now", "--prune=all") for s in ss):
            ctx.add("warn", "git gc --prune=now detected")
    elif sub == "update-ref":
        if "-d" in ss or "--delete" in ss:
            ctx.add("warn", "git update-ref -d detected")


# -- cloud / infra ----------------------------------------------------------

_AWS_LONG = ("--profile", "--region", "--output", "--endpoint-url", "--query", "--color",
             "--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout",
             "--cli-binary-format", "--page-size", "--max-items", "--starting-token")


def _c_aws(name, rest, ctx, stdin):
    pos, f, _, _ = _opts_all(rest, 0, "", _AWS_LONG)
    if len(pos) < 2:
        return
    svc, op = pos[0].s.lower(), pos[1].s.lower()
    if svc == "s3":
        if op == "rm" and "--recursive" in f:
            ctx.add("warn", "aws s3 rm --recursive detected")
        elif op == "rb" and "--force" in f:
            ctx.add("warn", "aws s3 rb --force detected")
        elif op == "sync" and "--delete" in f:
            ctx.add("warn", "aws s3 sync --delete detected")
    elif op.startswith(("delete-", "terminate-")):
        ctx.add("warn", f"aws {svc} {op} detected")


def _c_gsutil(name, rest, ctx, stdin):
    j, _, _ = _opts(rest, 0, "ohiu")
    if j >= len(rest):
        return
    sub = rest[j].s.lower()
    sargs = rest[j + 1 :]
    short = _short_chars(sargs)
    if sub == "rm" and (any(c in short for c in "rRa") or any("**" in a.s for a in sargs)):
        ctx.add("warn", "gsutil rm -r detected")
    elif sub == "rb":
        ctx.add("warn", "gsutil rb detected")
    elif sub == "rsync" and "d" in short:
        ctx.add("warn", "gsutil rsync -d detected")


def _c_gcloud(name, rest, ctx, stdin):
    pos, f, _, _ = _opts_all(rest, 0, "", ("--project", "--account", "--configuration"))
    names = [a.s for a in pos]
    if names[:2] == ["storage", "rm"] and f & {"-r", "-R", "--recursive"}:
        ctx.add("warn", "gcloud storage rm --recursive detected")
    elif "delete" in names[:4]:
        ctx.add("warn", f"gcloud {' '.join(names[: names.index('delete') + 1])} detected")


def _c_gh(name, rest, ctx, stdin):
    pos, _, v, _ = _opts_all(rest, 0, "RX", ("--repo", "--method"))
    names = [a.s for a in pos]
    if len(names) >= 2 and names[1] == "delete":
        ctx.add("warn", f"gh {names[0]} delete detected")
    if names[:1] == ["api"] and any(m.upper() == "DELETE" for m in v.get("-X", []) + v.get("--method", [])):
        ctx.add("warn", "gh api DELETE detected")


_KUBE_LONG = ("--namespace", "--context", "--cluster", "--user", "--kubeconfig", "--server",
              "--token", "--as", "--as-group", "--as-uid", "--certificate-authority",
              "--client-certificate", "--client-key", "--cache-dir", "--request-timeout",
              "--tls-server-name", "--selector", "--output", "--filename", "--container",
              "--field-selector", "--label-columns", "--sort-by", "--template",
              "--grace-period", "--timeout", "--patch", "--type", "--kustomize", "--v")


def _c_kubectl(name, rest, ctx, stdin):
    pos, _, _, tail = _opts_all(rest, 0, "nslofcLpkv", _KUBE_LONG)
    names = [a.s for a in pos]
    if names[:1] == ["delete"]:
        ctx.add("warn", "kubectl delete detected")
    elif names[:1] == ["drain"] or (names[:1] == ["replace"] and any(a.s == "--force" for a in rest)):
        ctx.add("warn", f"kubectl {names[0]} detected")
    elif names[:1] == ["exec"] and tail:
        _exec(tail, ctx, stdin)


def _c_helm(name, rest, ctx, stdin):
    pos, _, _, _ = _opts_all(
        rest, 0, "n",
        ("--namespace", "--kube-context", "--kubeconfig", "--kube-apiserver", "--kube-as-user",
         "--kube-as-group", "--kube-token", "--kube-ca-file", "--registry-config",
         "--repository-cache", "--repository-config", "--burst-limit", "--qps"),
    )
    if pos and pos[0].s in ("uninstall", "delete", "del", "un"):
        ctx.add("warn", "helm uninstall detected")


def _c_terraform(name, rest, ctx, stdin):
    names = [a.s for a in rest if not a.s.startswith("-")]
    if names[:1] == ["destroy"]:
        ctx.add("warn", f"{name} destroy detected")
    elif names[:1] == ["apply"] and any(a.s in ("-destroy", "--destroy") for a in rest):
        ctx.add("warn", f"{name} apply -destroy detected")


def _c_iac_destroy(name, rest, ctx, stdin):
    names = [a.s for a in rest if not a.s.startswith("-")]
    if "destroy" in names[:2] or names[:2] == ["run-all", "destroy"]:
        ctx.add("warn", f"{name} destroy detected")


def _c_dropdb(name, rest, ctx, stdin):
    ctx.add("warn", f"{name} detected")


def _c_mysqladmin(name, rest, ctx, stdin):
    if any(a.s == "drop" for a in rest):
        ctx.add("critical", "mysqladmin drop detected")


def _c_sqlq(name, rest, ctx, stdin):
    nxt = False
    for a in rest:
        if nxt:
            _check_sql(a.s, ctx)
            nxt = False
        elif a.s in ("-q", "--query", "-e", "--execute", "-c", "--command"):
            nxt = True
        elif a.s.startswith(("--query=", "--execute=")):
            _check_sql(a.s.split("=", 1)[1], ctx)


def _c_zfs(name, rest, ctx, stdin):
    if rest and rest[0].s == "destroy":
        ctx.add("warn", f"{name} destroy detected")
    elif name == "zpool" and rest and rest[0].s in ("labelclear",):
        ctx.add("warn", f"zpool {rest[0].s} detected")


def _c_nvme(name, rest, ctx, stdin):
    if rest and rest[0].s in ("format", "sanitize"):
        ctx.add("critical", f"nvme {rest[0].s} detected")


def _c_az(name, rest, ctx, stdin):
    names = [a.s for a in rest if not a.s.startswith("-")]
    if "delete" in names[:4] or "purge" in names[:4]:
        ctx.add("warn", f"az {' '.join(names[:3])} detected")


def _c_oc(name, rest, ctx, stdin):
    names = [a.s for a in rest if not a.s.startswith("-")]
    if names[:1] == ["delete"]:
        ctx.add("warn", f"{name} delete detected")
    else:
        _c_kubectl(name, rest, ctx, stdin)


def _c_openssl(name, rest, ctx, stdin):
    for k, a in enumerate(rest):
        if a.s == "-out" and k + 1 < len(rest):
            _check_write(rest[k + 1], ctx, append=False, trunc_only=False, via="openssl -out")


def _compose(args: Sequence[Arg], ctx: Ctx) -> None:
    pos, f, _, _ = _opts_all(
        args, 0, "fpt",
        ("--file", "--project-name", "--project-directory", "--env-file", "--profile", "--ansi",
         "--progress", "--parallel", "--rmi", "--timeout"),
    )
    if pos and pos[0].s == "down" and f & {"-v", "--volumes"}:
        ctx.add("warn", "docker compose down -v detected (removes volumes)")


def _c_docker(name, rest, ctx, stdin):
    if name == "docker-compose":
        _compose(rest, ctx)
        return
    j, _, _ = _opts(rest, 0, "Hcl", ("--host", "--context", "--config", "--log-level",
                                     "--tlscacert", "--tlscert", "--tlskey"))
    if j >= len(rest):
        return
    sub = rest[j].s
    sargs = rest[j + 1 :]
    nxt = [a.s for a in sargs if not a.s.startswith("-")]
    if sub == "volume" and nxt[:1] and nxt[0] in ("rm", "remove", "prune"):
        ctx.add("warn", f"{name} volume {nxt[0]} detected")
    elif sub == "system" and nxt[:1] == ["prune"]:
        ctx.add("warn", f"{name} system prune detected")
    elif sub == "compose":
        _compose(sargs, ctx)


# -- databases --------------------------------------------------------------

_SQL_START = frozenset(
    {"DROP", "DELETE", "UPDATE", "ALTER", "INSERT", "SELECT", "CREATE", "WITH", "MERGE",
     "REPLACE", "UPSERT"}
)
_SQL_KEYWORD_RE = re.compile(
    r"\b(?:DROP|DELETE|TRUNCATE|ALTER|CREATE|INSERT|UPDATE|SELECT)\b", re.IGNORECASE
)
_DROP_DATABASE = re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE)
_DROP_TABLE = re.compile(r"\bDROP\s+(?:TABLE|SCHEMA)\b", re.IGNORECASE)
_TRUNCATE = re.compile(r"\bTRUNCATE\b", re.IGNORECASE)
_DELETE_FROM = re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE)
_UPDATE_SET = re.compile(
    r"\bUPDATE\s+(?:ONLY\s+)?[^\s;]+(?:\s+(?:AS\s+)?[A-Za-z_][A-Za-z0-9_]*)?\s+SET\b",
    re.IGNORECASE,
)
_WHERE = re.compile(r"\bWHERE\b", re.IGNORECASE)
_MONGO_DROPDB = re.compile(r"\bdropDatabase\s*\(")
_MONGO_DROP = re.compile(r"\.drop\s*\(\s*\)")
_MONGO_DELETE_ALL = re.compile(r"\b(?:deleteMany|remove)\s*\(\s*\{\s*\}\s*\)")
_REDIS_FLUSH = re.compile(r"\bFLUSH(?:ALL|DB)\b", re.IGNORECASE)


def _sql_strip(sql: str) -> str:
    """Remove comments and blank out string literals (linear time)."""
    out: List[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
            continue
        if c == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            out.append("''")
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _check_sql(sql: str, ctx: Ctx) -> None:
    for stmt in _sql_strip(sql).split(";"):
        if _DROP_DATABASE.search(stmt):
            ctx.add("critical", "DROP DATABASE detected")
        if _DROP_TABLE.search(stmt):
            ctx.add("warn", "DROP TABLE detected")
        if _TRUNCATE.search(stmt):
            ctx.add("warn", "TRUNCATE detected")
        if _DELETE_FROM.search(stmt) and not _WHERE.search(stmt):
            ctx.add("warn", "DELETE FROM without WHERE detected")
        if _UPDATE_SET.search(stmt) and not _WHERE.search(stmt):
            ctx.add("warn", "UPDATE without WHERE detected")


def _stdin_text(stdin: Optional[Stdin]) -> Optional[str]:
    if stdin is not None and stdin.kind in ("heredoc", "herestring", "pipe"):
        return stdin.text
    return None


def _check_sql_stdin(stdin: Optional[Stdin], ctx: Ctx) -> None:
    text = _stdin_text(stdin)
    if text:
        _check_sql(text, ctx)


def _c_psql(name, rest, ctx, stdin):
    pos, _, v, _ = _opts_all(
        rest, 0, "cdfhpUvoLPFRT",
        ("--command", "--dbname", "--file", "--host", "--port", "--username", "--set",
         "--variable", "--output", "--log-file", "--pset", "--field-separator",
         "--record-separator", "--table-attr"),
    )
    sqls = v.get("-c", []) + v.get("--command", [])
    files = v.get("-f", []) + v.get("--file", [])
    for sql in sqls:
        _check_sql(sql, ctx)
    if sqls and pos:
        _check_sql(" ".join(sqls + [a.s for a in pos]), ctx)
    if not sqls and (not files or "-" in files):
        _check_sql_stdin(stdin, ctx)


def _c_mysql(name, rest, ctx, stdin):
    pos, _, v, _ = _opts_all(
        rest, 0, "euhPDS",
        ("--execute", "--user", "--host", "--port", "--database", "--socket"),
        short_opt="p",
    )
    sqls = v.get("-e", []) + v.get("--execute", [])
    for sql in sqls:
        _check_sql(sql, ctx)
    if sqls and pos:
        _check_sql(" ".join(sqls + [a.s for a in pos]), ctx)
    if not sqls:
        _check_sql_stdin(stdin, ctx)


_SQLITE_VALUE_OPTS = frozenset(
    {"separator", "nullvalue", "newline", "init", "vfs", "mmap", "maxsize", "A",
     "pagecache", "lookaside", "heap", "escape"}
)


def _c_sqlite(name, rest, ctx, stdin):
    sqls: List[str] = []
    pos: List[Arg] = []
    k, n = 0, len(rest)
    while k < n:
        a = rest[k]
        if _is_opt(a):
            opt = a.s.lstrip("-")
            if opt == "cmd" and k + 1 < n:
                sqls.append(rest[k + 1].s)
                k += 2
                continue
            k += 2 if opt in _SQLITE_VALUE_OPTS else 1
            continue
        pos.append(a)
        k += 1
    sqls += [a.s for a in pos[1:]]
    if len(pos) == 1 and _SQL_KEYWORD_RE.search(pos[0].s):
        sqls.append(pos[0].s)
    for sql in sqls:
        _check_sql(sql, ctx)
    if len(pos) <= 1:
        _check_sql_stdin(stdin, ctx)


def _check_mongo(js: str, ctx: Ctx) -> None:
    if _MONGO_DROPDB.search(js):
        ctx.add("critical", "MongoDB dropDatabase detected")
    if _MONGO_DROP.search(js):
        ctx.add("warn", "MongoDB collection drop detected")
    if _MONGO_DELETE_ALL.search(js):
        ctx.add("warn", "MongoDB delete-all detected")


def _c_mongo(name, rest, ctx, stdin):
    _, _, v, _ = _opts_all(rest, 0, "", ("--eval", "--file", "--host", "--port", "--username",
                                         "--password", "--authenticationDatabase"))
    evals = v.get("--eval", [])
    for js in evals:
        _check_mongo(js, ctx)
    if not evals:
        text = _stdin_text(stdin)
        if text:
            _check_mongo(text, ctx)


def _c_redis(name, rest, ctx, stdin):
    if {a.s.upper() for a in rest} & {"FLUSHALL", "FLUSHDB"}:
        ctx.add("warn", "redis-cli FLUSHALL/FLUSHDB detected")
        return
    text = _stdin_text(stdin)
    if text and _REDIS_FLUSH.search(text):
        ctx.add("warn", "redis-cli FLUSHALL/FLUSHDB detected")


# -- interpreters -----------------------------------------------------------

_PY_NAME_RE = re.compile(r"(?:python|pypy)[0-9.]*")
_PERL_NAME_RE = re.compile(r"perl[0-9.]*")
_RUBY_NAME_RE = re.compile(r"ruby[0-9.]*")
_PHP_NAME_RE = re.compile(r"php[0-9.]*")

_CODE_MUTATION_RE = re.compile(
    r"\b(?:os\.remove|os\.unlink|os\.rmdir|os\.removedirs|rmtree|remove_tree|rm_rf|rm_r|"
    r"rmSync|rmdirSync|unlinkSync|unlink|ftruncate|truncateSync|FileUtils\.(?:rm\w*|remove\w*)|"
    r"File\.delete|Files\.delete\w*|Dir\.(?:rmdir|delete|unlink)|rimraf|deleteRecursively)\b"
    r"|\.(?:rm|rmdir|truncate)\s*\(|\btruncate\s*\("
)
_CODE_DYNAMIC_RE = re.compile(
    r"\b(?:__import__|importlib|getattr|eval|exec|compile|Function|instance_eval|class_eval|"
    r"module_eval|send|public_send|const_get|constantize)\s*\(|__builtins__"
)
_CODE_SHELL_RE = re.compile(
    r"\b(?:system|popen\w*|exec\w*|spawn\w*|subprocess|child_process|check_output|check_call|"
    r"getoutput|getstatusoutput|Popen|shell_exec|passthru|proc_open|Open3|qx)\b|%x|`"
)
_OPEN_WRITE_RE = re.compile(
    r"\bopen\s*\([^\n]{0,200}?,\s*(?:mode\s*=\s*)?['\"][bt]*w[bt+]*['\"]"
    r"|\bopen\s*\(?[^\n]{0,200}?,\s*['\"]\+?>(?!>)"
)
_STRING_LIT_RE = re.compile(r"""'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`""")
_CONCAT_RE = re.compile(r"""(['"])\s*\+\s*\1""")
_LIST_LIT_RE = re.compile(r"\[([^\[\]]*)\]")
_SPAWN_RE = re.compile(r"""(['"])([^'"\n]{1,200})\1\s*,\s*\[([^\[\]]*)\]""")
_CODE_ESCAPES = {"n": "\n", "t": "\t"}


def _unescape_code(s: str) -> str:
    return re.sub(r"\\(.)", lambda m: _CODE_ESCAPES.get(m.group(1), m.group(1)), s)


def _interp_lang(name: str) -> Optional[str]:
    if _PY_NAME_RE.fullmatch(name):
        return "python"
    if _PERL_NAME_RE.fullmatch(name):
        return "perl"
    if _RUBY_NAME_RE.fullmatch(name):
        return "ruby"
    if name in ("node", "nodejs", "bun"):
        return "node"
    if name == "deno":
        return "deno"
    if _PHP_NAME_RE.fullmatch(name):
        return "php"
    return None


def _code_arg(a: Arg, value: str) -> Arg:
    return Arg(value, a.dyn, a.sub)


def _parse_python(rest: List[Arg]):
    k, n = 0, len(rest)
    while k < n:
        a = rest[k]
        s = a.s
        if s == "-":
            return [], "stdin", None
        if s == "--":
            k += 1
            break
        if not _is_opt(a):
            break
        if s.startswith("--"):
            k += 2 if s == "--check-hash-based-pycs" else 1
            continue
        step = 1
        for idx in range(1, len(s)):
            ch = s[idx]
            if ch == "c":
                value = s[idx + 1 :]
                if value:
                    return [_code_arg(a, value)], "inline", None
                return ([rest[k + 1]] if k + 1 < n else []), "inline", None
            if ch == "m":
                return [], "module", None
            if ch in "WX":
                if not s[idx + 1 :]:
                    step = 2
                break
        k += step
    if k < n:
        return [], "file", rest[k]
    return [], "stdin", None


def _parse_short_code(rest: List[Arg], code_chars: str, sep_val: str, attached: str):
    """perl/ruby/php style: collect -e code; skip options with values."""
    codes: List[Arg] = []
    k, n = 0, len(rest)
    while k < n:
        a = rest[k]
        s = a.s
        if s == "--":
            k += 1
            break
        if s == "-":
            return codes, ("inline" if codes else "stdin"), None
        if not _is_opt(a):
            break
        if s.startswith("--"):
            k += 1
            continue
        step = 1
        for idx in range(1, len(s)):
            ch = s[idx]
            value = s[idx + 1 :]
            if ch in code_chars:
                if value:
                    codes.append(_code_arg(a, value))
                elif k + 1 < n:
                    codes.append(rest[k + 1])
                    step = 2
                break
            if ch in sep_val:
                if not value and k + 1 < n:
                    step = 2
                break
            if ch in attached:
                break
        k += step
    if codes:
        return codes, "inline", None
    if k < n:
        return codes, "file", rest[k]
    return codes, "stdin", None


def _parse_node(rest: List[Arg]):
    codes: List[Arg] = []
    k, n = 0, len(rest)
    while k < n:
        a = rest[k]
        s = a.s
        if s == "-":
            return codes, ("inline" if codes else "stdin"), None
        if s == "--":
            k += 1
            break
        if not _is_opt(a):
            break
        if s in ("-e", "--eval", "-p", "--print", "-pe", "-ep"):
            if k + 1 < n:
                codes.append(rest[k + 1])
            k += 2
            continue
        if s.startswith(("--eval=", "--print=")):
            codes.append(_code_arg(a, s.split("=", 1)[1]))
        elif s in ("-r", "--require", "--import", "--loader", "--experimental-loader", "-C",
                   "--conditions", "--input-type", "--env-file", "--title"):
            k += 1
        k += 1
    if codes:
        return codes, "inline", None
    if k < n:
        return codes, "file", rest[k]
    return codes, "stdin", None


def _check_code(code: str, name: str, ctx: Ctx) -> None:
    merged = _CONCAT_RE.sub("", code)
    if _CODE_MUTATION_RE.search(code) or _CODE_MUTATION_RE.search(merged):
        ctx.add("warn", f"destructive {name} script detected")
    if _OPEN_WRITE_RE.search(code):
        ctx.add("warn", f"{name} script opens a file for writing (truncates it)")
    if _CODE_DYNAMIC_RE.search(code):
        ctx.add("warn", f"dynamic code execution in {name} script detected")
    if not _CODE_SHELL_RE.search(code):
        return
    literals: List[str] = []
    for m in _STRING_LIT_RE.finditer(merged):
        if len(literals) >= MAX_CODE_LITERALS:
            ctx.add("warn", f"{name} script runs shell commands with too many strings to inspect")
            break
        literals.append(_unescape_code(m.group()[1:-1]))
    for lit in literals:
        if lit.strip():
            _analyze_text(lit, ctx, None, strict=False)

    def items(text: str) -> List[str]:
        return [_unescape_code(x.group()[1:-1]) for x in _STRING_LIT_RE.finditer(text)]

    for m in _SPAWN_RE.finditer(merged):
        argv = [_unescape_code(m.group(2))] + items(m.group(3))
        _analyze_text(" ".join(shlex.quote(x) for x in argv), ctx, None, strict=False)
    for m in _LIST_LIT_RE.finditer(merged):
        argv = items(m.group(1))
        if len(argv) > 1:
            _analyze_text(" ".join(shlex.quote(x) for x in argv), ctx, None, strict=False)


def _c_interp(name, rest, ctx, stdin):
    lang = _interp_lang(name)
    if lang == "python":
        codes, mode, file_arg = _parse_python(rest)
    elif lang == "perl":
        codes, mode, file_arg = _parse_short_code(rest, "eE", "I", "Mmilx0CdDV")
    elif lang == "ruby":
        codes, mode, file_arg = _parse_short_code(rest, "e", "rICE", "Fix0WKT")
    elif lang == "php":
        codes, mode, file_arg = _parse_short_code(rest, "rBRE", "cdzf", "")
    elif lang == "deno":
        if rest[:1] and rest[0].s == "eval":
            codes, mode, file_arg = list(rest[1:2]), "inline", None
        else:
            codes, mode, file_arg = [], "file", None
    else:
        codes, mode, file_arg = _parse_node(rest)

    for code in codes:
        if code.sub:
            ctx.add("warn", f"{name} inline code built from command substitution cannot be verified")
        _check_code(code.s, name, ctx)
    if mode == "file" and file_arg is not None and file_arg.procsub:
        ctx.add("warn", f"{name} reading code from process substitution detected")
    if mode != "stdin" or stdin is None or stdin.kind == "file":
        return
    if stdin.kind in ("heredoc", "herestring"):
        _check_code(stdin.text or "", name, ctx)
    elif stdin.kind == "pipe":
        ctx.add("warn", f"pipeline into {name} interpreter detected")
        if stdin.text:
            _check_code(stdin.text, name, ctx)
    else:
        ctx.add("warn", f"{name} reading code from process substitution detected")


_SHELLS = ("sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "rbash", "fish", "yash")

_COMMANDS = {
    **{s: _c_shell for s in _SHELLS},
    "source": _c_source,
    ".": _c_source,
    "eval": _c_eval,
    "alias": _c_alias,
    "unalias": _c_unalias,
    "export": _c_declare,
    "declare": _c_declare,
    "typeset": _c_declare,
    "local": _c_declare,
    "readonly": _c_declare,
    "unset": _c_unset,
    "cd": _c_cd,
    "pushd": _c_cd,
    "popd": _c_cd,
    "rm": _c_rm,
    "chmod": _c_chmod,
    "chown": _c_chmod,
    "chgrp": _c_chmod,
    "mv": _c_mv,
    "cp": _c_cp,
    "tee": _c_tee,
    "dd": _c_dd,
    "truncate": _c_truncate,
    "shred": _c_shred,
    "mke2fs": _c_mkfs,
    "mkswap": _c_mkfs,
    "newfs": _c_mkfs,
    "wipefs": _c_wipefs,
    "blkdiscard": _c_blkdiscard,
    "sgdisk": _c_sgdisk,
    "find": _c_find,
    "rsync": _c_rsync,
    "crontab": _c_crontab,
    "git": _c_git,
    "aws": _c_aws,
    "gsutil": _c_gsutil,
    "gcloud": _c_gcloud,
    "gh": _c_gh,
    "kubectl": _c_kubectl,
    "helm": _c_helm,
    "terraform": _c_terraform,
    "tofu": _c_terraform,
    "terragrunt": _c_iac_destroy,
    "pulumi": _c_iac_destroy,
    "cdk": _c_iac_destroy,
    "cdktf": _c_iac_destroy,
    "dropdb": _c_dropdb,
    "dropuser": _c_dropdb,
    "mysqladmin": _c_mysqladmin,
    "clickhouse-client": _c_sqlq,
    "clickhouse": _c_sqlq,
    "cockroach": _c_sqlq,
    "zfs": _c_zfs,
    "zpool": _c_zfs,
    "nvme": _c_nvme,
    "az": _c_az,
    "oc": _c_oc,
    "openssl": _c_openssl,
    "docker": _c_docker,
    "podman": _c_docker,
    "docker-compose": _c_docker,
    "psql": _c_psql,
    "mysql": _c_mysql,
    "mariadb": _c_mysql,
    "sqlite3": _c_sqlite,
    "mongosh": _c_mongo,
    "mongo": _c_mongo,
    "redis-cli": _c_redis,
}


# ---------------------------------------------------------------------------
# Public analysis API
# ---------------------------------------------------------------------------

_DEPTH_REASON = f"{REASON_PREFIX} command nesting too deep to analyze; defaulting to ask"
_SIZE_REASON = f"{REASON_PREFIX} command larger than 64 KB is too large to analyze; defaulting to ask"


def _too_large(command: str) -> bool:
    return len(command) > MAX_COMMAND_BYTES or len(command.encode("utf-8", "replace")) > MAX_COMMAND_BYTES


def analyze(command: str, cwd: Optional[str] = None) -> List[Tuple[str, str, Optional[str]]]:
    """Return findings as (severity, reason, segment); severity is critical|warn.

    segment is the simple command that triggered the finding (used for allow
    rules), or None when the finding must not be overridable.
    """
    if not command or not command.strip():
        return []
    if _too_large(command):
        return [("warn", _SIZE_REASON, None)]
    ctx = Ctx(os.path.abspath(cwd) if cwd else os.getcwd())
    ctx.segment = command.strip()
    try:
        script = parse_script(command, 0)
        _run_script(script, ctx, None)
    except ParseError as e:
        return [("warn", f"{REASON_PREFIX} could not parse command ({e}); defaulting to ask", command.strip())]
    except (GuardLimit, RecursionError):
        return ctx.findings + [("warn", _DEPTH_REASON, None)]
    return ctx.findings


def _worst(findings) -> Optional[Tuple[str, str]]:
    for sev, reason, _ in findings:
        if sev == "critical":
            return ("deny", reason)
    for sev, reason, _ in findings:
        return ("ask", reason)
    return None


def analyze_command(command: str, cwd: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """Analyze a shell command without config: ('deny'|'ask', reason) or None."""
    return _worst(analyze(command, cwd))


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def _read_config_file(path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except FileNotFoundError:
        return None, None
    except (OSError, UnicodeDecodeError) as e:
        return None, f"{path}: unreadable ({e.__class__.__name__})"
    try:
        data = json.loads(raw)
    except ValueError:
        return None, f"{path}: invalid JSON"
    if not isinstance(data, dict):
        return None, f"{path}: top-level value must be an object"
    return data, None


def _validate_config(data: Dict[str, Any], path: str, allow_ok: bool):
    out: Dict[str, Any] = {}
    errors: List[str] = []
    for key in ("allow", "deny", "ask"):
        if key not in data or (key == "allow" and not allow_ok):
            continue
        value = data[key]
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            errors.append(f"{path}: '{key}' must be a list of strings")
            continue
        patterns = []
        for pat in value:
            try:
                patterns.append(re.compile(pat))
            except re.error:
                errors.append(f"{path}: invalid regex in '{key}': {pat!r}")
        out[key] = patterns
    if "mode" in data:
        mode = data["mode"]
        if mode is not None and mode not in ("ask", "deny"):
            errors.append(f"{path}: 'mode' must be \"ask\" or \"deny\"")
        else:
            out["mode"] = mode
    return out, errors


def load_config(cwd: Optional[str] = None) -> Dict[str, Any]:
    """Merge ~/.config/agent-guard/config.json and <cwd>/.agent-guard.json.

    The project-local file can only tighten: its "allow" key is ignored because
    an agent can write it with its file-editing tools.
    """
    home = os.path.expanduser("~")
    global_path = os.path.join(home, ".config", "agent-guard", "config.json")
    if cwd is None:
        cwd = os.getcwd()
    local_path = os.path.join(cwd, ".agent-guard.json")
    cfg: Dict[str, Any] = {"allow": [], "deny": [], "ask": [], "mode": None, "errors": []}
    sources = [(global_path, True)]
    if os.path.abspath(local_path) != os.path.abspath(global_path):
        sources.append((local_path, False))
    modes = []
    for path, allow_ok in sources:
        data, err = _read_config_file(path)
        if err:
            cfg["errors"].append(err)
        if data is None:
            continue
        part, errors = _validate_config(data, path, allow_ok)
        cfg["errors"].extend(errors)
        for key in ("allow", "deny", "ask"):
            cfg[key].extend(part.get(key, []))
        modes.append(part.get("mode"))
    if "deny" in modes:
        cfg["mode"] = "deny"
    elif "ask" in modes:
        cfg["mode"] = "ask"
    return cfg


def apply_config(
    command: str,
    findings: List[Tuple[str, str, Optional[str]]],
    config: Dict[str, Any],
) -> Optional[Tuple[str, str]]:
    """Combine analyzer findings with config rules.

    deny rules (re.search on the whole command) always deny. allow rules must
    re.fullmatch the simple command that produced a finding, and can only clear
    non-critical findings. ask rules and mode can only make decisions stricter.
    """
    errors = config.get("errors") or []
    for pat in config.get("deny") or []:
        if pat.search(command):
            return ("deny", f"{REASON_PREFIX} matched deny rule: {pat.pattern}")

    allow = [] if errors else (config.get("allow") or [])
    kept = [
        (sev, reason, seg)
        for sev, reason, seg in findings
        if not (sev == "warn" and seg is not None and any(p.fullmatch(seg) for p in allow))
    ]
    worst = _worst(kept)
    if worst and worst[0] == "deny":
        return worst
    if errors:
        return ("ask", f"{REASON_PREFIX} invalid config ({errors[0]}); defaulting to ask")
    if worst:
        reason = worst[1]
        if config.get("mode") == "deny":
            return ("deny", reason.replace("detected", "blocked").rstrip(".") + " (mode=deny)")
        return ("ask", reason)
    for pat in config.get("ask") or []:
        if pat.search(command):
            return ("ask", f"{REASON_PREFIX} matched ask rule: {pat.pattern}")
    return None


def decide(command: str, cwd: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """Full decision pipeline."""
    if os.environ.get("AGENT_GUARD_DISABLE") == "1":
        return None
    config = load_config(cwd)
    return apply_config(command, analyze(command, cwd), config)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def hook_output(decision: str, reason: str) -> Dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT,
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def emit_hook(decision: str, reason: str) -> None:
    print(json.dumps(hook_output(decision, reason), separators=(",", ":")))


def _extract_hook_command(data: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (command, cwd, error). command=None means ignore non-Bash events."""
    if not isinstance(data, dict):
        return None, None, "top-level JSON payload must be an object"

    tool_name = data.get("tool_name")
    if tool_name is None:
        tool_name = data.get("toolName") or ""
    if tool_name and not isinstance(tool_name, str):
        return None, None, "tool_name must be a string"
    if tool_name and tool_name != "Bash":
        return None, None, None

    tool_input = data.get("tool_input")
    if tool_input is None:
        tool_input = data.get("toolInput")
    if tool_input is None:
        tool_input = {}
    if not isinstance(tool_input, dict):
        return None, None, "tool_input must be an object"

    command = tool_input.get("command")
    if command is None and isinstance(data.get("command"), str):
        command = data.get("command")
    if not isinstance(command, str) or not command.strip():
        return None, None, "missing command string"

    cwd = data.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        cwd = os.getcwd()
    return command, cwd, None


def run_hook_stdin() -> int:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            emit_hook("ask", _FAIL_SAFE_REASON)
            return 0

        command, cwd, err = _extract_hook_command(data)
        if err:
            emit_hook("ask", _FAIL_SAFE_REASON)
            return 0
        if command is None:
            return 0

        result = decide(command, cwd=cwd)
        if result is None:
            return 0
        decision, reason = result
        emit_hook(decision, reason)
    except Exception:
        emit_hook("ask", _FAIL_SAFE_REASON)
    return 0


def run_check(command: str, codex: bool = False) -> int:
    try:
        result = decide(command)
    except Exception:
        result = ("ask", _INTERNAL_ERROR_REASON)
    if result is None:
        if not codex:
            print("allow")
        return 0
    decision, reason = result
    if codex:
        # Codex CLI hooks / generic wrappers: exit 2 + reason on stderr
        print(reason, file=sys.stderr)
        return 2
    print(f"{decision}: {reason}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    codex = False
    if "--codex" in argv:
        codex = True
        argv = [a for a in argv if a != "--codex"]

    if argv and argv[0] == "check":
        if len(argv) < 2:
            print("usage: agent_guard.py check \"<cmd>\" [--codex]", file=sys.stderr)
            return 1
        command = argv[1]
        return run_check(command, codex=codex)

    # Default: PreToolUse hook via stdin
    # --codex with stdin: still use exit-code protocol
    if codex:
        try:
            raw = sys.stdin.read()
            if not raw.strip():
                return 0
            data = json.loads(raw)
        except json.JSONDecodeError:
            print(_FAIL_SAFE_REASON, file=sys.stderr)
            return 2
        except Exception:
            print(_FAIL_SAFE_REASON, file=sys.stderr)
            return 2

        try:
            command, cwd, err = _extract_hook_command(data)
            if err:
                print(_FAIL_SAFE_REASON, file=sys.stderr)
                return 2
            if command is None:
                return 0
            result = decide(command, cwd=cwd)
            if result is None:
                return 0
            _, reason = result
            print(reason, file=sys.stderr)
            return 2
        except Exception:
            print(_FAIL_SAFE_REASON, file=sys.stderr)
            return 2

    return run_hook_stdin()


if __name__ == "__main__":
    sys.exit(main())
