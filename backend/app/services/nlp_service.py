import re
from app.models.schemas import SignalResult

URGENCY_PATTERNS = {
    "account_block": [
        r"account.{0,20}(blocked|suspended|deactivated|closed)",
        r"kyc.{0,20}(expire|pending|update|verify)",
        r"(update|complete).{0,20}kyc",
        r"account.{0,20}(24|48|72).{0,10}hours?",
    ],
    "authority_claim": [
        r"\b(rbi|sebi|income.?tax|it.?department|cyber.?cell|police)\b",
        r"\b(government|ministry|official)\b.{0,30}\b(notice|order|action)\b",
        r"aadhaar.{0,20}(link|update|expire|suspend)",
    ],
    "prize_scam": [
        r"(won|winner|selected|lucky).{0,20}(prize|reward|gift|cashback|lottery)",
        r"(claim|collect).{0,20}(reward|prize|money|amount)",
        r"₹\s*[\d,]+\s*(reward|cashback|prize|won)",
    ],
    "payment_urgency": [
        r"upi.{0,20}(expire|update|block|verify)",
        r"(pay|transfer|send).{0,20}(immediately|now|urgent|asap)",
        r"otp.{0,20}(share|tell|provide|give)",
    ],
    "fear_legal": [
        r"(legal|criminal|fir|arrest|warrant).{0,30}(action|case|filed|registered)",
        r"(penalt|fine|fee).{0,20}(₹|rs\.?|rupees?)",
        r"(last|final).{0,20}(warning|notice|chance|opportunity)",
    ],
}

HINDI_URGENCY = [
    "खाता बंद", "बैंक अकाउंट", "तुरंत", "अभी", "केवाईसी",
    "इनाम", "लॉटरी", "जीता", "पुरस्कार", "सत्यापित",
    "जल्दी करें", "अंतिम चेतावनी", "कार्रवाई होगी"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl", "t.ly", "rb.gy", "cutt.ly",
    "is.gd", "tiny.cc", "ow.ly", "goo.gl"
]

async def analyze_nlp(message: str) -> SignalResult:
    if not message or not message.strip():
        return SignalResult(score=0, flags=[], confidence=1.0, raw_data={"message": "empty"})

    score = 0
    flags = []
    raw = {"message_length": len(message), "tactics_found": []}
    message_lower = message.lower()

    # 1. Urgency patterns
    for tactic, patterns in URGENCY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, message_lower, re.IGNORECASE):
                score += 8
                flags.append(f"Urgency pattern: {tactic}")
                raw["tactics_found"].append(tactic)
                break

    # 2. Hindi keywords
    hindi_hits = [kw for kw in HINDI_URGENCY if kw in message]
    if hindi_hits:
        score += 10
        flags.append(f"Hindi urgency keywords: {', '.join(hindi_hits[:3])}")
        raw["hindi_keywords"] = hindi_hits

    # 3. URL shorteners
    found_short = [s for s in URL_SHORTENERS if s in message_lower]
    if found_short:
        score += 10
        flags.append(f"URL shortener detected: {found_short[0]}")
        raw["shorteners"] = found_short

    # 4. OTP sharing request
    otp_pattern = r"\b(otp|one.time.password|pin|password|cvv)\b.{0,30}\b(share|send|tell|give|enter|type)\b"
    if re.search(otp_pattern, message_lower):
        score += 15
        flags.append("OTP/password sharing requested — critical red flag")
        raw["otp_request"] = True

    # 5. Suspicious mobile numbers in banking context
    mobile_pattern = r"\b[6-9]\d{9}\b"
    mobiles = re.findall(mobile_pattern, message)
    banking_words = ["bank", "sbi", "hdfc", "rbi", "support", "helpline", "customer"]
    if mobiles and any(w in message_lower for w in banking_words):
        score += 8
        flags.append(f"Mobile number in banking context: {mobiles[0]}")
        raw["suspicious_numbers"] = mobiles

    # 6. Money amounts
    money_pattern = r"(?:₹|rs\.?|inr)\s*[\d,]+"
    money_hits = re.findall(money_pattern, message_lower)
    if money_hits:
        raw["money_mentioned"] = money_hits[:3]

    return SignalResult(
        score=min(score, 35),
        flags=flags,
        confidence=0.9 if len(message) > 20 else 0.5,
        raw_data=raw
    )