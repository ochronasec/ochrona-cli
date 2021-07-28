from datetime import timedelta
from typing import Any, Dict, Optional

import requests
import requests_cache  # type: ignore

# Cache settings
expire_after = timedelta(hours=1)
requests_cache.install_cache("pypi_cache", expire_after=expire_after)


def pypi_fetch(package: str) -> Optional[Dict[str, Any]]:
    """
    Get call to Pypi to fetch package detafgils
    """
    url = "https://pypi.org/pypi/{}/json".format(package)
    response = requests.request("GET", url)
    if response.status_code == 200:
        json = response.json()
        if json:
            return json
    return None
