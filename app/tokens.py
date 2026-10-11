"""Token counting shared by static checks, the judge, and the prober."""
import tiktoken

_ENC = tiktoken.get_encoding("cl100k_base")


def count_tokens(text: str) -> int:
    if not text:
        return 0
    return len(_ENC.encode(text, disallowed_special=()))
