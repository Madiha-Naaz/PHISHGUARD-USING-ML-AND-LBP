# feature_extraction.py
# Revised for robustness + fair handling of .gov.in / .edu.in style domains
# Returns feature values in {-1 (phishing), 0 (suspicious/unknown), 1 (legit)}

import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
from urllib.parse import urlparse

# ---------------------------
# Utility helpers
# ---------------------------

TRUSTED_PUBLIC_SECTOR_TLDS = (
    ".gov", ".gov.in", ".edu", ".edu.in", ".ac.in", ".nic.in", ".mil", ".gob", ".gouv", ".go.id"
)

SHORTENER_PATTERN = re.compile(
    r"(?:^|\.)("
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|"
    r"db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|"
    r"q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"
    r")$",
    re.IGNORECASE
)

STATUSBAR_PATTERN = re.compile(r"onmouseover\s*=", re.IGNORECASE)
DISABLE_RIGHTCLICK_PATTERN = re.compile(r"event\.button\s*==\s*2", re.IGNORECASE)
POPUP_PATTERN = re.compile(r"\balert\s*\(", re.IGNORECASE)
IFRAME_PATTERN = re.compile(r"<\s*iframe\b|<\s*frame\b", re.IGNORECASE)

BLACKLISTED_URL_PATTERN = re.compile(
    r"at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly",
    re.IGNORECASE
)

BLACKLISTED_IP_PATTERN = re.compile(
    r"(?:^|\.)(146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|"
    r"181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|"
    r"107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|"
    r"119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|"
    r"23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|"
    r"103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|"
    r"31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|"
    r"34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|"
    r"23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|"
    r"104\.130\.124\.96|47\.89\.58\.141|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|"
    r"110\.34\.231\.42)$",
    re.IGNORECASE
)

def is_ip_like_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def is_trusted_public_sector(domain: str) -> bool:
    d = domain.lower()
    return any(d.endswith(tld) for tld in TRUSTED_PUBLIC_SECTOR_TLDS)

def safe_whois(domain: str):
    try:
        return whois.whois(domain)
    except Exception:
        return None

def first_or_self(value):
    # whois library sometimes returns list of datetimes
    if isinstance(value, (list, tuple)) and value:
        return value[0]
    return value

def months_between(a: datetime, b: datetime) -> int:
    return (a.year - b.year) * 12 + (a.month - b.month)

def safe_get(url: str, timeout: int = 10):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        if 200 <= resp.status_code < 400:
            return resp
    except Exception:
        pass
    return None

# ---------------------------
# Main class
# ---------------------------

class FeatureExtraction:
    def __init__(self, url: str):
        self.features = []
        self.url = url.strip()
        self.urlparse = urlparse(self.url)
        self.domain = self.urlparse.netloc or ""
        # strip credentials if present (user:pass@host)
        if "@" in self.domain:
            self.domain = self.domain.split("@", 1)[-1]
        self.domain = self.domain.strip().strip("/").lower()
        self.response = safe_get(self.url)
        self.soup = BeautifulSoup(self.response.text, "html.parser") if self.response else None
        self.whois_response = safe_whois(self.domain) if self.domain else None

        # build features (order preserved)
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1. UsingIp: if host is an IP, suspicious
    def UsingIp(self):
        host = self.domain.split(":")[0]
        return -1 if is_ip_like_host(host) else 1

    # 2. longUrl
    def longUrl(self):
        L = len(self.url)
        if L < 54:
            return 1
        if 54 <= L <= 75:
            return 0
        return -1

    # 3. shortUrl (known shorteners)
    def shortUrl(self):
        try:
            host = self.domain
            if SHORTENER_PATTERN.search(host):
                return -1
            return 1
        except Exception:
            return 0

    # 4. Symbol @ in URL path/query → suspicious
    def symbol(self):
        return -1 if "@" in self.url else 1

    # 5. Redirecting // beyond scheme://
    def redirecting(self):
        try:
            # count '//' occurrences beyond the scheme
            after_scheme = self.url.split("://", 1)[-1]
            return -1 if "//" in after_scheme else 1
        except Exception:
            return 0

    # 6. prefixSuffix: hyphen in registered domain
    def prefixSuffix(self):
        try:
            host = self.domain.split(":")[0]
            # allow hyphens; mild signal only
            return 0 if "-" in host else 1
        except Exception:
            return 0

    # 7. SubDomains
    def SubDomains(self):
        try:
            host = self.domain.split(":")[0]
            # Split labels, ignore known public suffix chains like gov.in, edu.in, ac.in
            labels = host.split(".")
            if is_trusted_public_sector(host):
                # do NOT penalize multi-label public-sector domains
                return 1
            if len(labels) <= 2:
                return 1  # root or simple subdomain
            if len(labels) == 3:
                return 0
            return -1
        except Exception:
            return 0

    # 8. HTTPS present
    def Hppts(self):
        try:
            return 1 if self.urlparse.scheme == "https" else 0
        except Exception:
            return 0

    # 9. DomainRegLen (>= 12 months legit). Neutral for public-sector if unknown.
    def DomainRegLen(self):
        try:
            if not self.whois_response:
                return 1 if is_trusted_public_sector(self.domain) else 0
            exp = first_or_self(getattr(self.whois_response, "expiration_date", None))
            cre = first_or_self(getattr(self.whois_response, "creation_date", None))
            if not exp or not cre:
                return 1 if is_trusted_public_sector(self.domain) else 0
            # ensure datetime
            if isinstance(exp, date) and not isinstance(exp, datetime):
                exp = datetime(exp.year, exp.month, exp.day)
            if isinstance(cre, date) and not isinstance(cre, datetime):
                cre = datetime(cre.year, cre.month, cre.day)
            age_months = months_between(exp, cre)
            return 1 if age_months >= 12 else 0
        except Exception:
            return 1 if is_trusted_public_sector(self.domain) else 0

    # 10. Favicon (external favicons can be benign) → very soft signal
    def Favicon(self):
        try:
            if not self.soup:
                return 0
            host = self.domain
            for link in self.soup.find_all("link", href=True):
                href = link.get("href", "")
                if not href:
                    continue
                # resolve absolute hint
                if host in href or href.startswith("/") or href.startswith("./"):
                    return 1
            return 0
        except Exception:
            return 0

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            parts = self.domain.split(":")
            if len(parts) > 1:
                port = parts[1]
                return -1 if port not in ("80", "443") else 1
            return 1
        except Exception:
            return 0

    # 12. HTTPSDomainURL: 'https' string inside hostname is suspicious
    def HTTPSDomainURL(self):
        try:
            return -1 if "https" in self.domain.replace("https://", "") else 1
        except Exception:
            return 0

    # 13. RequestURL: proportion of resource URLs pointing to same domain
    def RequestURL(self):
        try:
            if not self.soup:
                return 0
            i, success = 0, 0
            host = self.domain
            def same_origin(src):
                return (host in src) or src.startswith("/") or src.startswith("./") or src.startswith("#") or src.startswith("data:")
            for tag, attr in (("img", "src"), ("audio", "src"), ("embed", "src"), ("iframe", "src")):
                for el in self.soup.find_all(tag, **{f"{attr}": True}):
                    src = el.get(attr, "") or ""
                    if not src:
                        continue
                    if same_origin(src):
                        success += 1
                    i += 1
            if i == 0:
                return 0
            pct = (success / float(i)) * 100.0
            if pct < 22.0:
                return 1
            elif pct < 61.0:
                return 0
            else:
                return -1
        except Exception:
            return 0

    # 14. AnchorURL: anchors pointing away or JS/mail links
    def AnchorURL(self):
        try:
            if not self.soup:
                return 0
            i, unsafe = 0, 0
            host = self.domain
            for a in self.soup.find_all("a", href=True):
                href = a.get("href", "") or ""
                href_l = href.lower()
                if (
                    "#" in href
                    or "javascript" in href_l
                    or "mailto:" in href_l
                    or not (host in href or href.startswith("/") or href.startswith("./"))
                ):
                    unsafe += 1
                i += 1
            if i == 0:
                return 0
            pct = (unsafe / float(i)) * 100.0
            if pct < 31.0:
                return 1
            elif pct < 67.0:
                return 0
            else:
                return -1
        except Exception:
            return 0

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            if not self.soup:
                return 0
            i, success = 0, 0
            host = self.domain
            def same_origin(u):
                return (host in u) or u.startswith("/") or u.startswith("./") or u.startswith("#") or u.startswith("data:")
            for link in self.soup.find_all("link", href=True):
                href = link.get("href", "") or ""
                if not href:
                    continue
                if same_origin(href):
                    success += 1
                i += 1
            for script in self.soup.find_all("script", src=True):
                src = script.get("src", "") or ""
                if not src:
                    continue
                if same_origin(src):
                    success += 1
                i += 1
            if i == 0:
                return 0
            pct = (success / float(i)) * 100.0
            if pct < 17.0:
                return 1
            elif pct < 81.0:
                return 0
            else:
                return -1
        except Exception:
            return 0

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if not self.soup:
                return 0
            forms = self.soup.find_all("form", action=True)
            if len(forms) == 0:
                return 1  # no forms → not phishing by this metric
            host = self.domain
            for form in forms:
                action = form.get("action", "") or ""
                al = action.lower()
                if action == "" or action == "about:blank":
                    return -1
                elif (host not in action) and (not action.startswith("/") and not action.startswith("./")):
                    return 0
            return 1
        except Exception:
            return 0

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if not self.response:
                return 0
            # presence of email collection might be neutral; mark suspicious only if many hits
            count = len(re.findall(r"mailto:|mail\(|contact@", self.response.text, flags=re.IGNORECASE))
            if count >= 3:
                return -1
            elif count >= 1:
                return 0
            else:
                return 1
        except Exception:
            return 0

    # 18. AbnormalURL (very noisy; keep neutral unless strong signal)
    def AbnormalURL(self):
        try:
            if not (self.response and self.whois_response):
                return 0
            # if WHOIS text exactly equals page text (highly unlikely), call abnormal
            whois_str = str(self.whois_response)
            return -1 if whois_str and whois_str.strip() == self.response.text.strip() else 1
        except Exception:
            return 0

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if not self.response:
                return 0
            hops = len(self.response.history)
            if hops <= 1:
                return 1
            elif hops <= 4:
                return 0
            else:
                return -1
        except Exception:
            return 0

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if not self.response:
                return 0
            return -1 if STATUSBAR_PATTERN.search(self.response.text) else 1
        except Exception:
            return 0

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if not self.response:
                return 0
            return 0 if DISABLE_RIGHTCLICK_PATTERN.search(self.response.text) else 1
        except Exception:
            return 0

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if not self.response:
                return 0
            # popups are common; make it a soft negative
            return 0 if POPUP_PATTERN.search(self.response.text) else 1
        except Exception:
            return 0

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if not self.response:
                return 0
            return 0 if IFRAME_PATTERN.search(self.response.text) else 1
        except Exception:
            return 0

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            if not self.whois_response:
                return 1 if is_trusted_public_sector(self.domain) else 0
            cre = first_or_self(getattr(self.whois_response, "creation_date", None))
            if not cre:
                return 1 if is_trusted_public_sector(self.domain) else 0
            if isinstance(cre, date) and not isinstance(cre, datetime):
                cre = datetime(cre.year, cre.month, cre.day)
            today = date.today()
            today_dt = datetime(today.year, today.month, today.day)
            age_m = months_between(today_dt, cre)
            return 1 if age_m >= 6 else 0
        except Exception:
            return 1 if is_trusted_public_sector(self.domain) else 0

    # 25. DNSRecording (proxy via whois creation presence)
    def DNSRecording(self):
        try:
            if not self.whois_response:
                return 1 if is_trusted_public_sector(self.domain) else 0
            cre = first_or_self(getattr(self.whois_response, "creation_date", None))
            if not cre:
                return 1 if is_trusted_public_sector(self.domain) else 0
            if isinstance(cre, date) and not isinstance(cre, datetime):
                cre = datetime(cre.year, cre.month, cre.day)
            today = date.today()
            today_dt = datetime(today.year, today.month, today.day)
            age_m = months_between(today_dt, cre)
            return 1 if age_m >= 6 else 0
        except Exception:
            return 1 if is_trusted_public_sector(self.domain) else 0

    # 26. WebsiteTraffic (Alexa retired) → neutral unless we can fetch something else
    def WebsiteTraffic(self):
        # Keep neutral; do NOT penalize .gov/.edu
        return 0

    # 27. PageRank (3rd-party sites unreliable). Neutral on failure.
    def PageRank(self):
        try:
            # Optional: you could integrate a reliable API here.
            return 0
        except Exception:
            return 0

    # 28. GoogleIndex (use googlesearch; neutral if blocked)
    def GoogleIndex(self):
        try:
            results = list(search(self.domain or self.url, num_results=3))
            return 1 if results else 0
        except Exception:
            return 0

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            if not self.response:
                return 0
            num = len(re.findall(r"<a\s+[^>]*href=", self.response.text, flags=re.IGNORECASE))
            if num == 0:
                return 0
            elif num <= 2:
                return 0
            else:
                return 1
        except Exception:
            return 0

    # 30. StatsReport (URL/IP blacklist)
    def StatsReport(self):
        try:
            if BLACKLISTED_URL_PATTERN.search(self.url):
                return -1
            ip_addr = socket.gethostbyname(self.domain.split(":")[0])
            if ip_addr and BLACKLISTED_IP_PATTERN.search(ip_addr):
                return -1
            return 1
        except Exception:
            return 1  # default to safe unless proven otherwise

    def getFeaturesList(self):
        return self.features
