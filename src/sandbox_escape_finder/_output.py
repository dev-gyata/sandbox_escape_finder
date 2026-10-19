"""Bounded text capture shared by the sandbox and child runner."""

import io


class _BoundedTextBuffer(io.TextIOBase):
    """A write-only prefix buffer; discarded output is never accumulated."""

    def __init__(self, max_chars: int) -> None:
        super().__init__()
        self._remaining = max_chars
        self._parts: list[str] = []

    def writable(self) -> bool:
        return True

    def write(self, text: str) -> int:
        if self.closed:
            raise ValueError("write to closed output capture")
        if not isinstance(text, str):
            raise TypeError("output capture requires str")
        if self._remaining and text:
            prefix = text[:self._remaining]
            self._parts.append(prefix)
            self._remaining -= len(prefix)
        return len(text)

    def getvalue(self) -> str:
        return "".join(self._parts)
