# SecuScope — Système de design UI (v1)

> Direction : **rapport d'audit premium, sombre, "verdict certifié"**.
> Référence visuelle canonique : `secuscope_report_reference.html` (le mock validé).
> Objectif de ce doc : rendre la direction **reproductible** et interdire les tells "IA générique".

---

## 0. Principes directeurs

1. **La couleur ne vient que du contenu.** Le chrome est neutre (near-black bleuté + texte). Les seules couleurs saturées sont (a) l'**aurora** de fond, signature de marque, et (b) l'**échelle de grades** (A→F), utilisée *uniquement dans la data* (scores, pills, cellules).
2. **Dépenser l'audace à un seul endroit.** L'élément mémorable est le **sceau-verdict** (le grade). Tout le reste reste calme pour le laisser ressortir.
3. **Un seul moment de motion orchestré** au chargement. Jamais de fade-up sur chaque section ni de transition sur chaque carte → c'est le tell "généré par IA".
4. **On observe, on ne décore pas.** Chaque filet, chiffre, cellule encode une info réelle. Pas de numérotation si ce n'est pas une séquence.

---

## 1. Tokens — couleurs

```css
:root{
  /* chrome (neutre) */
  --bg:#08090E;                      /* fond near-black bleuté */
  --panel:rgba(255,255,255,.028);    /* surface verre */
  --panel-2:rgba(255,255,255,.045);  /* surface relevée */
  --tx:#EDF0F6;                      /* texte principal */
  --muted:#98A3B4;                   /* texte secondaire */
  --faint:#636E80;                   /* texte tertiaire / labels */

  /* accents signature (aurora, interactif, glows) — PAS pour la data */
  --accent:#8B7CFF;                  /* violet */
  --accent2:#4DA6FF;                 /* bleu */
  --accent3:#34E0D0;                 /* teal */

  /* échelle de grades — UNIQUEMENT dans la data (scores, pills, cellules) */
  --a:#3FD17A;  /* A — émeraude */
  --b:#8AD15B;  /* B */
  --c:#F2B13D;  /* C — ambre */
  --d:#F58345;  /* D — orange */
  --f:#F2544B;  /* F — rouge */
}
```

Règle d'or : si tu hésites à colorer un élément de chrome, laisse-le neutre. Le violet/bleu/teal ne sert QU'à l'aurora, aux bordures/halos et aux micro-éléments d'accent (spark IA, point de la courbe).

---

## 2. Tokens — typographie

Trois familles (Google Fonts) :

- **Archivo** (700/800) — display : titres, score, grade, chiffres héro. Tracking serré (`-0.02em`).
- **IBM Plex Sans** (400/600/700) — UI & corps de texte.
- **IBM Plex Mono** (400/500/600) — **data** : labels techniques, valeurs, impacts, timestamps, légendes.

```html
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
```

Échelle indicative : héro titre 28px / score 60px / titres de carte 14px (Archivo 700) / corps 13–15px / data & légendes 10–12px (mono).

À ÉVITER (tells IA) : accentuer un seul mot d'un titre, les eyebrows en MAJUSCULES espacées partout, le mono utilisé comme déco plutôt que pour de la vraie data, le `→` collé aux boutons.

---

## 3. Techniques signature (le "craft")

### 3.1 Aurora de fond (dérive lente)
```css
.aurora{position:fixed;inset:-25%;z-index:-2;filter:blur(100px);opacity:.5;}
.aurora span{position:absolute;border-radius:50%;mix-blend-mode:screen;}
/* 3 taches : violet (#6B4BFF), bleu (#2E7DFF), teal (#22D3C2) */
@keyframes d1{0%,100%{transform:translate(0,0)}50%{transform:translate(6vw,4vw)}}
```
Trois `radial-gradient` floutés, animés sur 22–30s. C'est 80% de l'effet "waow".

### 3.2 Grain + grille pointillée
- Grain : overlay SVG `feTurbulence` en `opacity:.04` fixe (casse le "CSS plat").
- Grille pointillée masquée en haut du hero : `radial-gradient(rgba(255,255,255,.05) 1px, transparent 1px)` `background-size:26px`.

### 3.3 Carte verre + bordure dégradée spéculaire (l'arête "Linear")
```css
.glass{position:relative;background:var(--panel);backdrop-filter:blur(14px);border-radius:18px;
  box-shadow:0 30px 60px -40px rgba(0,0,0,.9);}
.glass::after{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;pointer-events:none;
  background:linear-gradient(160deg,rgba(255,255,255,.22),rgba(255,255,255,.03) 38%,rgba(255,255,255,0) 70%);
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor;mask-composite:exclude;}
```

### 3.4 Spotlight au survol
Une lueur accent qui suit le curseur (JS `pointermove` → `--mx/--my`), `radial-gradient` en `::before`, `opacity 0→1` au hover.

### 3.5 Sceau-verdict (élément signature)
Anneau d'instrument : 72 graduations + **guilloché gravé** (hypotrochoïde SVG, `opacity ~0.13`) + arc de score coloré au grade + grade en Archivo 800 avec `text-shadow` de la couleur du grade + halo flouté derrière. Voir le `<script>` du mock.

### 3.6 Courbe d'évolution (façon Linear)
Aire lissée (Catmull-Rom → bézier), `fill` dégradé accent→transparent, ligne 2.5px avec `drop-shadow` glow, bandes de grade en fond (C/D) très faibles, point de fin blanc cerclé accent.

### 3.7 Matrice de vulnérabilités (façon GitHub)
Grand bloc : catalogue COMPLET des contrôles en lignes par catégorie (Protocoles, Ciphers, Certificat, Vulns TLS, En-têtes, DNS, Cookies, Infra). Chaque case = un contrôle, colorée par statut : `ok`=vert (opacity .6) · `warn`=ambre · `vuln`=rouge + glow · `na`=gris. Tooltip au survol. Pied avec compteurs (vulnérables / à surveiller / total).

### 3.8 Radar "surface d'attaque"
Pentagone SVG, remplissage `radialGradient` accent, 5 axes (MITM, XSS, Clickjack, Sniffing, WAF).

---

## 4. Motion (règles strictes)

- **Une seule séquence au chargement** : (1) score compte 0→N, (2) arc du sceau se dessine, (3) ligne de la courbe se trace, (4) cartes montent (`translateY` + fade) en **cascade douce** via `animation-delay` croissant.
- Courbes : `cubic-bezier(.2,.7,.2,1)`, durées 0.7–1.4s.
- Interactions (hover/spotlight) : bienvenues, elles répondent à l'utilisateur.
- `@media (prefers-reduced-motion:reduce)` : tout statique, aurora figée.
- **Interdit** : fade-up sur chaque section au scroll, transition sur chaque carte, effets dispersés.

---

## 5. Inventaire des composants

| Composant | Rôle |
|---|---|
| Header sticky (glass blur) | wordmark dégradé, cible scannée, bouton "Nouveau scan" |
| Hero — carte verdict | sceau-verdict + titre + chips méta + bandeau de plafond |
| Carte radar | surface d'attaque estimée |
| Scorecards catégories (×4) | note /100 + poids + 2 déductions principales, filet de couleur en haut |
| Carte courbe | évolution du score dans le temps |
| Carte matrice | surface de vulnérabilités (catalogue complet) |
| Carte rapport IA | résumé exécutif + points techniques (filet accent, spark conique, badge "LLM · à vérifier") |
| Panels détail (TLS, DNS) | tables lignes : contrôle / résultat / statut (pill) / impact |
| Feed "à corriger" | findings priorisés, point de sévérité qui glow |

Layout clé : rangée `grid 1.6fr / 1fr` — gauche (courbe + matrice empilées, `flex:1` pour remplir) · droite (rapport IA, `flex` interne pour remplir) → **hauteurs égales, pas de trou**.

---

## 6. Copy (ton)

Voix active, phrase courte, sentence case. Les boutons disent l'action ("Auditer le domaine", "Nouveau scan"). Les findings expliquent quoi faire et pourquoi. Pas de jargon système exposé à l'utilisateur sans glose.

---

## 7. Garde-fous anti-"IA générique" (checklist)

- [ ] Pas de fond crème + serif + accent terracotta.
- [ ] Pas de near-black + un seul accent néon posé au hasard.
- [ ] Pas de kit de cartes SaaS identiques avec la même ombre grise molle.
- [ ] Pas d'eyebrow MAJUSCULE au-dessus de chaque titre.
- [ ] Pas de `→` sur les boutons/liens, pas de `A · B · C` en milieu de ligne systématique.
- [ ] Couleur de grade jamais utilisée pour du chrome ; accent jamais utilisé pour de la data.
- [ ] Un seul moment de motion, le reste répond à l'utilisateur.
