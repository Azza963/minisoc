# MiniSOC

Application légère de supervision défensive en laboratoire pour l'analyse de journaux **SSH** et **HTTP**, avec normalisation, règles de corrélation, historique **SQLite**, tableau de bord **Streamlit** et **export CSV**.

> **Cadre laboratoire** : MiniSOC est un outil pédagogique local d'analyse défensive. Une alerte est un indice documenté pour prioriser les vérifications, pas une conclusion qu'une attaque a réussi. Le projet ne comporte ni agent intrusif, ni accès distant, ni blocage ou réponse automatique, ni collecte en production, ni promesse d'exhaustivité.

## Structure du dépôt
- `app.py` : interface tableau de bord Streamlit et exports CSV.
- `parsers.py` : analyse et normalisation des logs SSH et HTTP en UTC ISO 8601.
- `rules.py` : règles de corrélation et génération d'alertes documentées.
- `db.py` : persistance SQLite (événements, alertes, historique d'imports).
- `DECISIONS.md` : choix d'architecture, hypothèses, cas limites et sources.
- `data/` et `tests/` : jeux de données d'exemple et tests.

## Installation et lancement (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py