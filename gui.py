
import tkinter as tk
from tkinter import font as tkfont
from functions import analyse_url


def run_check():
    """
    Called when the user clicks the 'Check URL' button.
    Reads the URL from the input box, analyses it,
    and displays the result in the result area.
    """
    url = url_entry.get()

    # Validate that the user typed something meaningful
    if url.strip() == "" or url.strip() == "https://":
        result_label.config(text="Please enter a URL first.", fg="#e67e22")
        detail_text.config(state=tk.NORMAL)
        detail_text.delete("1.0", tk.END)
        detail_text.config(state=tk.DISABLED)
        return

    analysis = analyse_url(url)
    verdict = analysis["verdict"]
    reasons = analysis["reasons"]
    score   = analysis["score"]

    # Display the verdict with colour coding
    if verdict == "Safe":
        result_label.config(text="✅  SAFE URL", fg="#27ae60")
    elif verdict == "Suspicious":
        result_label.config(text="⚠️  SUSPICIOUS URL", fg="#e67e22")
    else:
        result_label.config(text="❌  PHISHING URL — DO NOT VISIT", fg="#e74c3c")

    # Display reasons / details
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
    url_entry.insert(0, "https://")
    result_label.config(text="", fg="#2c3e50")
    detail_text.config(state=tk.NORMAL)
    detail_text.delete("1.0", tk.END)
    detail_text.config(state=tk.DISABLED)


# ============================================================
# BUILD THE TKINTER WINDOW
# ============================================================

def build_gui():
    """Construct and return the main Tkinter window."""
    global url_entry, result_label, detail_text

    root = tk.Tk()
    root.title("Fake URL Detector — Phishing Detection Tool")
    root.geometry("680x560")
    root.resizable(False, False)
    root.configure(bg="#f0f4f8")

    # ── Fonts ──
    title_font  = tkfont.Font(family="Arial", size=18, weight="bold")
    label_font  = tkfont.Font(family="Arial", size=11)
    button_font = tkfont.Font(family="Arial", size=11, weight="bold")
    result_font = tkfont.Font(family="Arial", size=14, weight="bold")
    detail_font = tkfont.Font(family="Courier", size=10)

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
    url_entry.insert(0, "https://")

    # ── Buttons ──
    btn_frame = tk.Frame(root, bg="#f0f4f8", padx=30)
    btn_frame.pack(fill=tk.X)

    tk.Button(
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
    ).pack(side=tk.LEFT, padx=(0, 10))

    tk.Button(
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
    ).pack(side=tk.LEFT)

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

    # Scrollbar and Text side by side — fixes the original bug
    text_frame = tk.Frame(detail_frame, bg="#f0f4f8")
    text_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

    scrollbar = tk.Scrollbar(text_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    detail_text = tk.Text(
        text_frame,
        font=detail_font,
        height=10,
        relief=tk.SOLID,
        bd=1,
        bg="#ffffff",
        fg="#2c3e50",
        state=tk.DISABLED,
        wrap=tk.WORD,
        yscrollcommand=scrollbar.set
    )
    detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
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

    return root
