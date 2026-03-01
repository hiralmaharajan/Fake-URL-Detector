

import tkinter as tk
from tkinter import font as tkfont

# ─────────────────────────────────────────────
# LIST OF KNOWN LEGITIMATE (TRUSTED) DOMAINS
# ─────────────────────────────────────────────
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


# ============================================================
# FUNCTION 1: Clean and normalise the URL
# ============================================================
def clean_url(url):
    """
    Remove whitespace from the URL and convert it to lowercase.
    This makes comparisons easier and consistent.

    Parameters:
        url (str): The raw URL typed by the user.

    Returns:
        str: A cleaned, lowercase version of the URL.
    """
    url = url.strip()       # remove leading/trailing spaces
    url = url.lower()       # convert to lowercase
    return url


# ============================================================
# FUNCTION 2: Check if the URL uses HTTPS
# ============================================================
def check_https(url):
    """
    Check whether the URL starts with 'https://'.
    HTTP-only URLs are less secure and often used in phishing.

    Parameters:
        url (str): The cleaned URL string.

    Returns:
        tuple: (bool flag, str reason)
               flag=True means a problem was found.
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
    Phishing sites often use IPs to hide their identity.

    Parameters:
        url (str): The cleaned URL string.

    Returns:
        tuple: (bool flag, str reason)
    """
    # Remove the protocol part
    stripped = url.replace("https://", "").replace("http://", "")
    # Get just the host (before any slash)
    host = stripped.split("/")[0]
    # Remove port number if present
    host = host.split(":")[0]

    # Split host by dots and check if all parts are digits
    parts = host.split(".")
    if len(parts) == 4:
        is_ip = True
        for part in parts:
            # Each part must be a number between 0 and 255
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
    URLs longer than 75 characters are often used in phishing
    to hide the real destination.

    Parameters:
        url (str): The cleaned URL string.

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
    Look for symbols that are commonly used in phishing URLs,
    such as '@', multiple hyphens, or multiple consecutive dots.

    Parameters:
        url (str): The cleaned URL string.

    Returns:
        tuple: (bool flag, str reason)
    """
    reasons = []

    # '@' symbol can be used to trick browsers into ignoring the real domain
    if "@" in url:
        reasons.append("URL contains '@' symbol (possible credential-hiding trick).")

    # Count hyphens in the domain part
    domain_part = url.replace("https://", "").replace("http://", "").split("/")[0]
    if domain_part.count("-") > 2:
        reasons.append("Domain contains too many hyphens (suspicious domain name).")

    # Multiple consecutive dots suggest a disguised subdomain
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

    Parameters:
        url (str): The cleaned URL string.

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
    Extract the domain from the URL and compare it against
    the list of known trusted domains.

    Parameters:
        url (str): The cleaned URL string.

    Returns:
        tuple: (bool is_trusted, str domain)
    """
    stripped = url.replace("https://", "").replace("http://", "")
    host = stripped.split("/")[0].split(":")[0]

    # Remove 'www.' prefix for fair comparison
    if host.startswith("www."):
        host = host[4:]

    for trusted in TRUSTED_DOMAINS:
        if host == trusted or host.endswith("." + trusted):
            return True, host

    return False, host


# ============================================================
# FUNCTION 8: Check for typosquatting (fake-looking domains)
# ============================================================
def check_typosquatting(domain):
    """
    Check if the domain looks like a misspelling of a trusted brand.
    For example: 'googl11e.com' looks like 'google.com' but is fake.

    This function uses a simple character-difference count
    (similar to edit distance) to detect near-matches.

    Parameters:
        domain (str): The extracted domain (without protocol/www).

    Returns:
        tuple: (bool flag, str reason)
    """
    # Known brand names to check against
    brand_names = [
        "google", "facebook", "amazon", "microsoft",
        "apple", "twitter", "paypal", "instagram",
        "netflix", "linkedin", "youtube"
    ]

    # Get just the name part (before the TLD)
    name_part = domain.split(".")[0] if "." in domain else domain

    for brand in brand_names:
        # Only compare if lengths are similar (within 4 characters)
        if abs(len(name_part) - len(brand)) <= 4:
            # Count how many characters differ (simple similarity check)
            differences = 0
            shorter = min(len(name_part), len(brand))
            for i in range(shorter):
                if name_part[i] != brand[i]:
                    differences += 1
            # Also add length difference to total differences
            differences += abs(len(name_part) - len(brand))

            # If quite similar but NOT identical, it may be typosquatting
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
            'score': int (risk score),
            'reasons': list of strings explaining the flags
        }
    """
    url = clean_url(url)

    # Dictionary to store results
    result = {
        "verdict": "Safe",
        "score": 0,
        "reasons": []
    }

    # --- Run check: Trusted domain ---
    is_trusted, domain = check_trusted_domain(url)

    # --- Run check: HTTPS ---
    flag, reason = check_https(url)
    if flag:
        result["score"] += 2
        result["reasons"].append(reason)

    # --- Run check: IP address ---
    flag, reason = check_ip_address(url)
    if flag:
        result["score"] += 4
        result["reasons"].append(reason)

    # --- Run check: URL length ---
    flag, reason = check_url_length(url)
    if flag:
        result["score"] += 1
        result["reasons"].append(reason)

    # --- Run check: Suspicious characters ---
    flag, reason = check_suspicious_characters(url)
    if flag:
        result["score"] += 3
        result["reasons"].append(reason)

    # --- Run check: Suspicious keywords ---
    flag, reason = check_suspicious_keywords(url)
    if flag:
        result["score"] += 2
        result["reasons"].append(reason)

    # --- Run check: Typosquatting ---
    flag, reason = check_typosquatting(domain)
    if flag:
        result["score"] += 5
        result["reasons"].append(reason)

    # --- Determine final verdict based on score ---
    if is_trusted and result["score"] == 0:
        result["verdict"] = "Safe"
    elif result["score"] >= 5:
        result["verdict"] = "Phishing"
    elif result["score"] >= 2:
        result["verdict"] = "Suspicious"
    else:
        result["verdict"] = "Safe"

    return result


# ============================================================
# GUI SECTION — Tkinter Form-Based Interface
# ============================================================

def run_check():
    """
    Called when the user clicks the 'Check URL' button.
    Reads the URL from the input box, analyses it,
    and displays the result in the result area.
    """
    url = url_entry.get()

    # Validate that the user typed something
    if url.strip() == "":
        result_label.config(text="Please enter a URL first.", fg="#e67e22")
        detail_text.config(state=tk.NORMAL)
        detail_text.delete("1.0", tk.END)
        detail_text.config(state=tk.DISABLED)
        return

    # Run the analysis
    analysis = analyse_url(url)
    verdict = analysis["verdict"]
    reasons = analysis["reasons"]
    score = analysis["score"]

    # Display the verdict with colour coding
    if verdict == "Safe":
        result_label.config(
            text="✅  SAFE URL",
            fg="#27ae60"
        )
    elif verdict == "Suspicious":
        result_label.config(
            text="⚠️  SUSPICIOUS URL",
            fg="#e67e22"
        )
    else:
        result_label.config(
            text="❌  PHISHING URL — DO NOT VISIT",
            fg="#e74c3c"
        )

    # Display the reasons / details
    detail_text.config(state=tk.NORMAL)
    detail_text.delete("1.0", tk.END)

    detail_text.insert(tk.END, f"Risk Score: {score}\n\n")

    if reasons:
        detail_text.insert(tk.END, "Reasons flagged:\n")
        for idx, reason in enumerate(reasons, start=1):
            detail_text.insert(tk.END, f"  {idx}. {reason}\n")
    else:
        detail_text.insert(tk.END, "No suspicious patterns detected.\n"
                                   "This URL appears to be safe.")

    detail_text.config(state=tk.DISABLED)


def clear_fields():
    """Clear the URL input field and result area."""
    url_entry.delete(0, tk.END)
    result_label.config(text="", fg="#2c3e50")
    detail_text.config(state=tk.NORMAL)
    detail_text.delete("1.0", tk.END)
    detail_text.config(state=tk.DISABLED)


# ============================================================
# BUILD THE TKINTER WINDOW
# ============================================================

# Create the main application window
root = tk.Tk()
root.title("Fake URL Detector — Phishing Detection Tool")
root.geometry("680x560")
root.resizable(False, False)
root.configure(bg="#f0f4f8")

# ── Fonts ──
title_font   = tkfont.Font(family="Arial", size=18, weight="bold")
label_font   = tkfont.Font(family="Arial", size=11)
button_font  = tkfont.Font(family="Arial", size=11, weight="bold")
result_font  = tkfont.Font(family="Arial", size=14, weight="bold")
detail_font  = tkfont.Font(family="Courier", size=10)

# ── Title Banner ──
banner = tk.Frame(root, bg="#2c3e50", pady=14)
banner.pack(fill=tk.X)

tk.Label(
    banner,
    text="🔒 Fake URL Detector",
    font=title_font,
    bg="#2c3e50",
    fg="#ecf0f1"
).pack()

tk.Label(
    banner,
    text="Phishing Detection Tool | 5T4017CMD",
    font=tkfont.Font(family="Arial", size=9),
    bg="#2c3e50",
    fg="#95a5a6"
).pack()

# ── URL Input Section ──
input_frame = tk.Frame(root, bg="#f0f4f8", pady=20, padx=30)
input_frame.pack(fill=tk.X)

tk.Label(
    input_frame,
    text="Enter URL to Check:",
    font=label_font,
    bg="#f0f4f8",
    fg="#2c3e50",
    anchor="w"
).pack(fill=tk.X)

url_entry = tk.Entry(
    input_frame,
    font=label_font,
    width=60,
    relief=tk.SOLID,
    bd=1,
    fg="#2c3e50"
)
url_entry.pack(fill=tk.X, pady=(6, 0), ipady=6)
url_entry.insert(0, "https://")  # default placeholder text

# ── Buttons ──
btn_frame = tk.Frame(root, bg="#f0f4f8", padx=30)
btn_frame.pack(fill=tk.X)

check_btn = tk.Button(
    btn_frame,
    text="🔍  Check URL",
    font=button_font,
    bg="#2980b9",
    fg="white",
    relief=tk.FLAT,
    padx=18,
    pady=8,
    cursor="hand2",
    command=run_check
)
check_btn.pack(side=tk.LEFT, padx=(0, 10))

clear_btn = tk.Button(
    btn_frame,
    text="🗑  Clear",
    font=button_font,
    bg="#95a5a6",
    fg="white",
    relief=tk.FLAT,
    padx=18,
    pady=8,
    cursor="hand2",
    command=clear_fields
)
clear_btn.pack(side=tk.LEFT)

# ── Result Label ──
result_label = tk.Label(
    root,
    text="",
    font=result_font,
    bg="#f0f4f8",
    fg="#2c3e50"
)
result_label.pack(pady=(20, 6))

# ── Detail Text Box ──
detail_frame = tk.Frame(root, bg="#f0f4f8", padx=30)
detail_frame.pack(fill=tk.BOTH, expand=True)

tk.Label(
    detail_frame,
    text="Analysis Details:",
    font=label_font,
    bg="#f0f4f8",
    fg="#2c3e50",
    anchor="w"
).pack(fill=tk.X)

detail_text = tk.Text(
    detail_frame,
    font=detail_font,
    height=10,
    relief=tk.SOLID,
    bd=1,
    bg="#ffffff",
    fg="#2c3e50",
    state=tk.DISABLED,
    wrap=tk.WORD
)
detail_text.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

# Scrollbar for the text box
scrollbar = tk.Scrollbar(detail_text)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
detail_text.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=detail_text.yview)

# ── Footer ──
footer = tk.Frame(root, bg="#bdc3c7", pady=4)
footer.pack(fill=tk.X, side=tk.BOTTOM)
tk.Label(
    footer,
    text="Softwarica College | Coventry University | Ethical Hacking & Cyber Security",
    font=tkfont.Font(family="Arial", size=8),
    bg="#bdc3c7",
    fg="#2c3e50"
).pack()

# ── Start the Application ──
root.mainloop()
