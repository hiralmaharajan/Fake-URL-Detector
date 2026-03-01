
TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "youtube.com", "amazon.com",
    "microsoft.com", "apple.com", "twitter.com", "instagram.com",
    "linkedin.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "bbc.com", "bbc.co.uk", "gov.uk", "ac.uk", "edu", "coventry.ac.uk"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "signin", "webscr",
    "free", "winner", "prize", "click", "urgent"
]

def clean_url(url):
    """
    Remove whitespace from the URL and convert it to lowercase.

    Parameters:
        url (str): The raw URL typed by the user.

    Returns:
        str: A cleaned, lowercase version of the URL.
    """
    url = url.strip()
    url = url.lower()
    return url


# ============================================================
# FUNCTION 2: Check if the URL uses HTTPS
# ============================================================
def check_https(url):
    """
    Check whether the URL starts with 'https://'.

    Returns:
        tuple: (bool flag, str reason)
    """
    if not url.startswith("https://"):
        return True, "URL does not use HTTPS (insecure connection detected)."
    return False, ""


# ============================================================
# FUNCTION 3: Check if the URL contains an IP address
# ============================================================
def check_ip_address(url):
    """
    Detect if the URL uses a raw IP address instead of a domain name.

    Returns:
        tuple: (bool flag, str reason)
    """
    stripped = url.replace("https://", "").replace("http://", "")
    host = stripped.split("/")[0].split(":")[0]
    parts = host.split(".")

    if len(parts) == 4:
        is_ip = True
        for part in parts:
            if not part.isdigit():
                is_ip = False
                break
            if int(part) < 0 or int(part) > 255:
                is_ip = False
                break
        if is_ip:
            return True, "URL contains an IP address instead of a domain name."
    return False, ""


# ============================================================
# FUNCTION 4: Check the length of the URL
# ============================================================
def check_url_length(url):
    """
    URLs longer than 75 characters are often used in phishing.

    Returns:
        tuple: (bool flag, str reason)
    """
    if len(url) > 75:
        return True, f"URL is very long ({len(url)} characters). Long URLs can hide malicious destinations."
    return False, ""


# ============================================================
# FUNCTION 5: Check for suspicious special characters
# ============================================================
def check_suspicious_characters(url):
    """
    Look for symbols commonly used in phishing URLs.

    Returns:
        tuple: (bool flag, str reason)
    """
    reasons = []

    if "@" in url:
        reasons.append("URL contains '@' symbol (possible credential-hiding trick).")

    domain_part = url.replace("https://", "").replace("http://", "").split("/")[0]
    if domain_part.count("-") > 2:
        reasons.append("Domain contains too many hyphens (suspicious domain name).")

    if ".." in url:
        reasons.append("URL contains consecutive dots (..) which is suspicious.")

    if reasons:
        return True, " | ".join(reasons)
    return False, ""


# ============================================================
# FUNCTION 6: Check for suspicious keywords in the URL
# ============================================================
def check_suspicious_keywords(url):
    """
    Scan the URL for common phishing-related keywords.

    Returns:
        tuple: (bool flag, str reason)
    """
    found_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url:
            found_keywords.append(keyword)

    if found_keywords:
        return True, f"URL contains suspicious keywords: {', '.join(found_keywords)}."
    return False, ""


# ============================================================
# FUNCTION 7: Check if the domain is a known trusted domain
# ============================================================
def check_trusted_domain(url):
    """
    Extract the domain and compare it against the trusted domains list.

    Returns:
        tuple: (bool is_trusted, str domain)
    """
    stripped = url.replace("https://", "").replace("http://", "")
    host = stripped.split("/")[0].split(":")[0]

    if host.startswith("www."):
        host = host[4:]

    for trusted in TRUSTED_DOMAINS:
        if host == trusted or host.endswith("." + trusted):
            return True, host

    return False, host


# ============================================================
# FUNCTION 8: Check for typosquatting
# ============================================================
def check_typosquatting(domain):
    """
    Check if the domain looks like a misspelling of a trusted brand.

    Parameters:
        domain (str): The extracted domain (without protocol/www).

    Returns:
        tuple: (bool flag, str reason)
    """
    brand_names = [
        "google", "facebook", "amazon", "microsoft",
        "apple", "twitter", "paypal", "instagram",
        "netflix", "linkedin", "youtube"
    ]

    name_part = domain.split(".")[0] if "." in domain else domain

    for brand in brand_names:
        if abs(len(name_part) - len(brand)) <= 4:
            differences = 0
            shorter = min(len(name_part), len(brand))
            for i in range(shorter):
                if name_part[i] != brand[i]:
                    differences += 1
            differences += abs(len(name_part) - len(brand))

            if 1 <= differences <= 4 and name_part != brand:
                return True, (
                    f"Domain '{domain}' looks similar to '{brand}.com' "
                    f"but is different — possible typosquatting."
                )

    return False, ""


# ============================================================
# FUNCTION 9: MAIN DETECTION ENGINE
# ============================================================
def analyse_url(url):
    """
    Run all detection checks on the URL and produce a final verdict.

    Parameters:
        url (str): The raw URL from the user input.

    Returns:
        dict: {
            'verdict': 'Safe' | 'Suspicious' | 'Phishing',
            'score': int,
            'reasons': list of strings
        }
    """
    url = clean_url(url)

    result = {
        "verdict": "Safe",
        "score": 0,
        "reasons": []
    }

    is_trusted, domain = check_trusted_domain(url)

    flag, reason = check_https(url)
    if flag:
        result["score"] += 2
        result["reasons"].append(reason)

    flag, reason = check_ip_address(url)
    if flag:
        result["score"] += 4
        result["reasons"].append(reason)

    flag, reason = check_url_length(url)
    if flag:
        result["score"] += 1
        result["reasons"].append(reason)

    flag, reason = check_suspicious_characters(url)
    if flag:
        result["score"] += 3
        result["reasons"].append(reason)

    flag, reason = check_suspicious_keywords(url)
    if flag:
        result["score"] += 2
        result["reasons"].append(reason)

    flag, reason = check_typosquatting(domain)
    if flag:
        result["score"] += 5
        result["reasons"].append(reason)

    if is_trusted and result["score"] == 0:
        result["verdict"] = "Safe"
    elif result["score"] >= 5:
        result["verdict"] = "Phishing"
    elif result["score"] >= 2:
        result["verdict"] = "Suspicious"
    else:
        result["verdict"] = "Safe"

    return result
