import re

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "iloveyou", "admin", "welcome", "monkey"
}

def analyze_password(pw: str) -> dict:
    """Return a detailed analysis and score for a password."""
    reasons = []
    tips = []
    score = 0

    pw_stripped = pw.strip()
    if pw_stripped != pw:
        tips.append("Avoid leading/trailing spaces (they can be removed accidentally).")
    pw = pw_stripped

    length = len(pw)
    if length < 8:
        reasons.append("Too short (less than 8 characters).")
        tips.append("Use at least 12 characters for better security.")
    elif length < 12:
        score += 1
        tips.append("Consider using 12+ characters for stronger security.")
    else:
        score += 2

    if re.search(r"[a-z]", pw):
        score += 1
    else:
        reasons.append("No lowercase letters.")
        tips.append("Add lowercase letters (a-z).")

    if re.search(r"[A-Z]", pw):
        score += 1
    else:
        reasons.append("No uppercase letters.")
        tips.append("Add uppercase letters (A-Z).")

    if re.search(r"\d", pw):
        score += 1
    else:
        reasons.append("No numbers.")
        tips.append("Add numbers (0-9).")

    if re.search(r"[^\w\s]", pw):
        score += 1
    else:
        reasons.append("No special characters.")
        tips.append("Add special characters (e.g., !@#$%).")

    # Penalize very common passwords
    if pw.lower() in COMMON_PASSWORDS:
        score = max(score - 2, 0)
        reasons.append("Password is too common.")
        tips.append("Avoid common passwords and predictable patterns.")

    # Penalize repeated characters (e.g., aaaaaa, 111111)
    if re.fullmatch(r"(.)\1{5,}", pw):
        score = max(score - 2, 0)
        reasons.append("Repeated characters detected.")
        tips.append("Avoid repeating the same character many times.")

    # Penalize simple sequences (e.g., 12345, abcde)
    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz"]
    pw_lower = pw.lower()
    for seq in sequences:
        for i in range(len(seq) - 4):
            chunk = seq[i:i+5]
            if chunk in pw_lower:
                score = max(score - 1, 0)
                reasons.append("Simple sequence detected (e.g., 12345 or abcde).")
                tips.append("Avoid sequences like 12345 or abcde.")
                break

    # Clamp score to 0..7
    score = max(0, min(score, 7))

    if score <= 2:
        rating = "Weak"
    elif score <= 4:
        rating = "Medium"
    else:
        rating = "Strong"

    return {
        "rating": rating,
        "score": score,
        "max_score": 7,
        "reasons": reasons,
        "tips": list(dict.fromkeys(tips))  # remove duplicates, keep order
    }

def main():
    print("Password Strength Checker")
    print("-" * 28)
    pw = input("Enter a password to check: ")

    if not pw.strip():
        print("\nResult: Weak (empty or whitespace only)")
        print("Tip: Use a longer password with a mix of letters, numbers, and symbols.")
        return

    result = analyze_password(pw)

    print(f"\nResult: {result['rating']}  (Score: {result['score']}/{result['max_score']})")

    if result["reasons"]:
        print("\nIssues found:")
        for r in result["reasons"]:
            print(f" - {r}")

    print("\nRecommendations:")
    for t in result["tips"]:
        print(f" - {t}")

if __name__ == "__main__":
    main()
