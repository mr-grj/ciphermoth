from collections.abc import Callable
from inspect import unwrap
from typing import cast
from urllib.parse import SplitResult, urlsplit

# urllib.parse caches entire inputs, including vault URLs and TOTP setup keys.
# Use its same parser without the memoizing wrapper so plaintext stays local.
split_url = cast(Callable[[str], SplitResult], unwrap(urlsplit))
