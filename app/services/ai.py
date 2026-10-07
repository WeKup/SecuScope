from google import genai
import hashlib
import logging
import json
import time

from app.services.scoring import deduction_severity, failure_label

logger = logging.getLogger(__name__)

# À incrémenter quand le prompt change : invalide les rapports mis en cache avec l'ancien prompt.
PROMPT_VERSION = "2026-10-v3"

# À incrémenter quand le prompt change : invalide les rapports mis en cache avec l'ancien prompt.
PROMPT_VERSION = "2026-10-v3"

DEFAULT_RISKS = {"mitm": 0, "xss": 0, "clickjacking": 0, "sniffing": 0, "waf": 0}


def _fallback_report(reason):
    """Rapport vide marqué indisponible. La raison est loguée, jamais stockée ni affichée."""
    logger.error("Rapport IA indisponible : %s", reason)
    return {
        "executive": "",
        "technical": [],
        "risks": DEFAULT_RISKS.copy(),
        "ai_unavailable": True,
    }


def _extract_json_object(text):
    clean_text = (text or "").replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(clean_text)
    except json.JSONDecodeError:
        start = clean_text.find("{")
        end = clean_text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        return json.loads(clean_text[start:end + 1])


def _normalize_report(data):
    if not isinstance(data, dict):
        return _fallback_report("Réponse IA invalide (JSON non objet)")

    executive = data.get("executive")
    technical = data.get("technical")
    risks = data.get("risks")

    if not isinstance(executive, str) or not executive.strip():
        return _fallback_report("Réponse IA sans résumé exploitable")

    if isinstance(technical, str):
        technical = [technical]
    elif not isinstance(technical, list):
        technical = []

    normalized_risks = DEFAULT_RISKS.copy()
    if isinstance(risks, dict):
        for key in normalized_risks:
            try:
                normalized_risks[key] = max(0, min(100, int(risks.get(key, 0))))
            except (TypeError, ValueError):
                normalized_risks[key] = 0

    return {
        "executive": executive.strip(),
        "technical": [str(item) for item in technical[:6]],
        "risks": normalized_risks,
    }


def _format_dns_security(dns_sec):
    """Résume dns_security pour le prompt ; tolère l'absence de la clé ou d'un contrôle."""
    if not isinstance(dns_sec, dict) or not dns_sec:
        return "- Analyse DNS non disponible pour cet audit (ne pas en tirer de conclusion)."

    def section(key):
        value = dns_sec.get(key)
        return value if isinstance(value, dict) else {}

    def unverified(info):
        return info.get("status", "error") == "error"

    lines = []

    spf = section("spf")
    if unverified(spf):
        lines.append("- SPF : non vérifié (erreur DNS)")
    elif spf["status"] == "absent":
        lines.append("- SPF : ABSENT (usurpation d'e-mail facilitée)")
    else:
        termination = spf.get("termination")
        note = " (PERMISSIF : autorise tout expéditeur)" if termination == "+all" else ""
        lines.append(f"- SPF : présent, terminaison {termination}{note}")

    dmarc = section("dmarc")
    if unverified(dmarc):
        lines.append("- DMARC : non vérifié (erreur DNS)")
    elif dmarc["status"] == "absent":
        lines.append("- DMARC : ABSENT")
    else:
        policy = dmarc.get("policy")
        note = " (surveillance seule, aucun blocage)" if policy == "none" else ""
        lines.append(f"- DMARC : présent, p={policy}{note}")

    dnssec = section("dnssec")
    if unverified(dnssec):
        lines.append("- DNSSEC : non vérifié (erreur DNS)")
    else:
        lines.append(f"- DNSSEC : {'actif' if dnssec.get('enabled') else 'inactif'}")

    caa = section("caa")
    if unverified(caa):
        lines.append("- CAA : non vérifié (erreur DNS)")
    elif caa["status"] == "present":
        lines.append(f"- CAA : présent, AC autorisées : {caa.get('authorities', [])}")
    else:
        lines.append("- CAA : absent")

    axfr = section("axfr")
    if unverified(axfr):
        lines.append("- Transfert de zone AXFR : non vérifié (erreur DNS)")
    elif axfr["status"] == "vulnerable":
        lines.append(
            "- Transfert de zone AXFR : OUVERT = FAILLE CRITIQUE sur "
            f"{axfr.get('vulnerable_nameservers', [])} (toute la zone DNS est exposée)"
        )
    else:
        lines.append("- Transfert de zone AXFR : fermé")

    dkim = section("dkim")
    if not unverified(dkim):
        found = dkim.get("selectors_found", [])
        lines.append(
            f"- DKIM (indice, sélecteurs courants uniquement) : {found}"
            if found else
            "- DKIM (indice) : aucun sélecteur courant trouvé (n'implique pas l'absence de DKIM)"
        )

    return "\n".join(lines)


def _severity_summary(scan_data):
    """Classement critique / moyenne / faible, identique à celui affiché par le dashboard.

    Sert à imposer au LLM le vocabulaire de SecuScope : « critique » = faille plafonnante."""
    breakdown = scan_data.get("score_breakdown")
    categories = breakdown.get("categories") if isinstance(breakdown, dict) else None
    buckets = {"critical": [], "medium": [], "low": []}
    if scan_data.get("critical_failure"):
        buckets["critical"].append(failure_label(scan_data))
    if isinstance(categories, dict):
        for cat in categories.values():
            for ded in (cat.get("deductions") or []) if isinstance(cat, dict) else []:
                label, points = str(ded.get("label")), int(ded.get("points") or 0)
                buckets[deduction_severity(label, points)].append(f"{label} (−{points})")

    def fmt(items):
        return " ; ".join(items) if items else "aucune"

    unread = [str(cat.get("label")) for cat in (categories or {}).values()
              if isinstance(cat, dict) and cat.get("evaluated") is False]
    lines = [
        f"- Grade : {scan_data.get('score', '?')} ({scan_data.get('numeric_score', 'N/A')}/100)",
        f"- CRITIQUES ({len(buckets['critical'])}), failles plafonnantes : {fmt(buckets['critical'])}",
        f"- MOYENNES ({len(buckets['medium'])}) : {fmt(buckets['medium'])}",
        f"- FAIBLES ({len(buckets['low'])}) : {fmt(buckets['low'])}",
    ]
    if unread and not scan_data.get("critical_failure"):
        lines.append(f"- Catégories NON LUES (analyse incomplète) : {', '.join(unread)}. "
                     "Ne conclus rien sur elles et signale que l'analyse est incomplète.")
    return "\n".join(lines)


def _format_http(scan_data):
    """En-têtes et cookies pour le prompt ; « non analysés » quand la réponse HTTPS n'a pas été lue."""
    if scan_data.get("critical_failure") or scan_data.get("http_readable") is False:
        return ("- En-têtes de sécurité et cookies : NON ANALYSÉS (réponse HTTPS non lue ou scan interrompu). "
                "Ne conclus rien sur leur présence ou leur absence.")
    present = [k for k, v in scan_data.get("headers", {}).items() if "✅" in str(v)]
    lines = [
        f"- Headers présents : {present}",
        f"- Headers manquants : {scan_data.get('missing_headers', [])}",
        "  (réellement absents de la réponse HTTP ; un CDN/WAF n'implique aucune protection de leur part, "
        "recommande de les ajouter)",
        f"- Cookies : {scan_data.get('cookies_security', [])}",
    ]
    return "\n".join(lines)


def _format_waf(scan_data):
    """Couches WAF/CDN pour le prompt : le multi-couches est signalé, un cache n'est pas une protection."""
    layers = scan_data.get("waf_layers")
    if not isinstance(layers, list) or not layers:
        return f"- WAF/CDN : {scan_data.get('waf_detected', 'Non détecté')}"
    real = [l["name"] for l in layers if isinstance(l, dict) and l.get("protective")]
    other = [l["name"] for l in layers if isinstance(l, dict) and not l.get("protective")]
    line = f"- WAF/CDN : {len(real)} couche(s) protectrice(s) distincte(s) : {' + '.join(real) or 'aucune'}"
    if other:
        line += f" ; détecté mais sans être une protection (cache, routeur) : {', '.join(other)}"
    if len(real) > 1:
        line += ". Plusieurs couches de protection : mentionne-le, ne parle pas d'un seul WAF."
    return line


def _build_prompt(scan_data):
    waf_line = _format_waf(scan_data)
    http_lines = _format_http(scan_data)
    dns_summary = _format_dns_security(scan_data.get('dns_security', {}))
    severity = _severity_summary(scan_data)
    return f"""
Tu es un expert en cybersécurité (Audit Black Box).
Analyse ce domaine : {scan_data['domain']}

Données collectées :
- Score actuel : {scan_data.get('numeric_score', 'N/A')}/100
- SSL Issuer : {scan_data['ssl'].get('issuer')}
{waf_line}
- Serveur : {scan_data.get('server')}
- Stack technique : {scan_data.get('tech_stack', [])}
{http_lines}

Sécurité DNS / e-mail :
{dns_summary}

Classement de sévérité SecuScope (c'est la référence, à reprendre tel quel) :
{severity}

VOCABULAIRE DE SÉVÉRITÉ (obligatoire) : utilise « critique », « moyenne » et « faible » exactement
comme classés ci-dessus, jamais ta propre échelle.
- « Critique » est réservé aux failles de la ligne CRITIQUES (faille plafonnante : HTTP en clair,
  handshake TLS échoué, certificat invalide, SSLv2/SSLv3 accepté, AXFR ouvert, cipher cassé).
- DNSSEC absent, CAA absent, en-têtes manquants, SPF en ~all, cookies sans attribut : « moyenne »
  ou « faible » selon le classement, JAMAIS « critique », « grave », « majeure » ni
  « vulnérabilité critique ».
- Si la ligne CRITIQUES indique « aucune », n'emploie pas le mot « critique » ; sinon, une faille
  critique doit apparaître comme telle et le site ne doit pas être qualifié de robuste.
- Reste cohérent avec le grade et avec les nombres ci-dessus : n'invente ni grade ni comptage.

CONSIGNE : tiens compte des failles DNS ci-dessus dans "executive" et "technical".
Ne déduis rien d'un contrôle « non vérifié » ou « non disponible ».

TÂCHE : Génère un JSON BRUT UNIQUEMENT (pas de markdown, pas de texte avant/après) avec 3 clés :
1. "executive": Résumé dirigeant (2 phrases, ton professionnel).
2. "technical": Liste de 4 points techniques actionnables précis.
3. "risks": Objet JSON avec niveau de protection (0-100) pour :
   - "mitm": (basé sur HSTS + SSL valide)
   - "xss": (basé sur CSP)
   - "clickjacking": (basé sur X-Frame-Options)
   - "sniffing": (basé sur X-Content-Type-Options)
   - "waf": (basé sur WAF détecté + infrastructure)
"""


def posture_signature(scan_data):
    """Empreinte stable de la posture vue par l'IA : domaine, score, détail par catégorie (notes et
    déductions), cap, couches WAF/CDN et mode d'échec. Deux scans à posture identique ont la même
    signature : le rapport IA du premier peut être réutilisé sans rappeler le modèle."""
    breakdown = scan_data.get("score_breakdown") or {}
    categories = breakdown.get("categories") or {}
    cap = breakdown.get("cap") or {}
    payload = {
        "prompt": PROMPT_VERSION,
        "domain": scan_data.get("domain"),
        "score": scan_data.get("numeric_score"),
        "grade": scan_data.get("score"),
        "categories": {
            key: {
                "score": cat.get("score"),
                "evaluated": cat.get("evaluated", True),
                "findings": sorted((str(d.get("label")), d.get("points")) for d in cat.get("deductions") or []),
            }
            for key, cat in sorted(categories.items()) if isinstance(cat, dict)
        },
        "cap": {"max": cap.get("max"), "reasons": sorted(cap.get("reasons") or [])},
        "waf": sorted((str(l.get("name")), bool(l.get("protective")))
                      for l in scan_data.get("waf_layers") or [] if isinstance(l, dict)),
        "failure": [bool(scan_data.get("critical_failure")), scan_data.get("failure_kind")],
        "http_readable": scan_data.get("http_readable"),
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_valid_report(report):
    """Un rapport réutilisable : généré par le modèle, avec résumé et points techniques."""
    return (isinstance(report, dict) and report.get("ai_unavailable") is not True
            and isinstance(report.get("executive"), str) and bool(report["executive"].strip())
            and isinstance(report.get("technical"), list) and bool(report["technical"]))


def posture_signature(scan_data):
    """Empreinte stable de la posture vue par l'IA : domaine, score, détail par catégorie (notes et
    déductions), cap, couches WAF/CDN et mode d'échec. Deux scans à posture identique ont la même
    signature : le rapport IA du premier peut être réutilisé sans rappeler le modèle."""
    breakdown = scan_data.get("score_breakdown") or {}
    categories = breakdown.get("categories") or {}
    cap = breakdown.get("cap") or {}
    payload = {
        "prompt": PROMPT_VERSION,
        "domain": scan_data.get("domain"),
        "score": scan_data.get("numeric_score"),
        "grade": scan_data.get("score"),
        "categories": {
            key: {
                "score": cat.get("score"),
                "evaluated": cat.get("evaluated", True),
                "findings": sorted((str(d.get("label")), d.get("points")) for d in cat.get("deductions") or []),
            }
            for key, cat in sorted(categories.items()) if isinstance(cat, dict)
        },
        "cap": {"max": cap.get("max"), "reasons": sorted(cap.get("reasons") or [])},
        "waf": sorted((str(l.get("name")), bool(l.get("protective")))
                      for l in scan_data.get("waf_layers") or [] if isinstance(l, dict)),
        "failure": [bool(scan_data.get("critical_failure")), scan_data.get("failure_kind")],
        "http_readable": scan_data.get("http_readable"),
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_valid_report(report):
    """Un rapport réutilisable : généré par le modèle, avec résumé et points techniques."""
    return (isinstance(report, dict) and report.get("ai_unavailable") is not True
            and isinstance(report.get("executive"), str) and bool(report["executive"].strip())
            and isinstance(report.get("technical"), list) and bool(report["technical"]))


def generate_report(scan_data, api_key, model_id):
    if not api_key:
        return _fallback_report("Aucune clé API Gemini (GOOGLE_API_KEY absente et pas de clé de session)")
    try:
        client = genai.Client(api_key=api_key)
        prompt = _build_prompt(scan_data)

        for attempt in range(3):
            try:
                response = client.models.generate_content(model=model_id, contents=prompt)
                break
            except Exception as e:
                if "503" in str(e) and attempt < 2:
                    time.sleep(3)
                    continue
                raise e
        return _normalize_report(_extract_json_object(response.text))
    except Exception as e:
        return _fallback_report(f"erreur GenAI ({model_id}) : {e}")
