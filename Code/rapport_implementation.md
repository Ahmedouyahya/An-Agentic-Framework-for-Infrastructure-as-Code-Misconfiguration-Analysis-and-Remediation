# Rapport d'Implémentation
## Framework Agentique pour l'Analyse et la Remédiation des Misconfigurations IaC

**Étudiant :** Ahmedou Yahye Kheyri
**Encadreur :** Hala Bezine
**Date :** Mars 2026
**Faculté des Sciences de Sfax — Master MRSI**

---

## 1. Résumé du Travail Accompli

Le rapport bibliographique (rapport1.pdf) a établi les fondements théoriques du framework et identifié les limitations des systèmes RAG passifs. Ce document de rapport d'implémentation décrit **comment construire concrètement** le prototype, les choix techniques motivés, l'organisation du code, le dataset de test, et le plan d'évaluation.

---

## 2. Organisation du Projet (Structure `Code/`)

```
Code/
├── src/
│   ├── agent/orchestrator.py       ← Agent central (orchestrateur du pipeline)
│   ├── analyzer/contextual.py      ← Analyse contextuelle (détection outil + smells)
│   ├── knowledge/
│   │   ├── knowledge_base.py       ← Base vectorielle (ChromaDB)
│   │   └── retriever.py            ← Récupération RAG/CRAG
│   ├── generator/fix_generator.py  ← Génération de patches (LLM)
│   ├── validator/tool_integrator.py← Validation externe (Checkov)
│   └── formatter/patch_formatter.py← Formatage diff + explication CWE
├── dataset/
│   ├── terraform/                  ← 3 fichiers Terraform insécurisés
│   ├── ansible/                    ← 2 playbooks Ansible insécurisés
│   ├── kubernetes/                 ← 2 manifests K8s insécurisés
│   ├── docker/                     ← 1 Dockerfile insécurisé
│   └── metadata.json               ← Index du dataset (27 smells étiquetés)
├── tests/test_validator.py         ← Tests Checkov sur le dataset
├── scripts/run_checkov.sh          ← Script de scan complet du dataset
└── requirements.txt                ← Dépendances Python
```

---

## 3. Description du Dataset

### 3.1 Composition

Le dataset comprend **8 fichiers IaC** couvrant 4 outils, avec **27 security smells** labelisés manuellement selon la taxonomie de War et al. (2025) — 62 catégories, alignée CWE.

| Outil       | Fichiers | Smells |
|-------------|----------|--------|
| Terraform   | 3        | 11     |
| Ansible     | 2        | 7      |
| Kubernetes  | 2        | 8      |
| Docker      | 1        | 5      |
| **Total**   | **8**    | **27** |

### 3.2 Catégories de Smells Couverts

| Catégorie (Rahman et al.)  | Exemples dans le dataset                          |
|----------------------------|---------------------------------------------------|
| **Security**               | Hardcoded passwords, privileged containers, open CIDR 0.0.0.0/0 |
| **Configuration Data**     | Versioning désactivé, backups désactivés          |
| **Dependency**             | Image `latest` non épinglée, pas de resource limits |

### 3.3 CWEs Représentés

| CWE      | Description                              | Occurrences |
|----------|------------------------------------------|-------------|
| CWE-250  | Unnecessary Privileges                   | 8           |
| CWE-732  | Incorrect Permission Assignment          | 8           |
| CWE-259  | Use of Hard-coded Password               | 6           |
| CWE-312  | Cleartext Storage of Sensitive Info      | 3           |
| CWE-400  | Uncontrolled Resource Consumption        | 2           |
| CWE-295  | Improper Certificate Validation          | 1           |

### 3.4 Checkov IDs Testés

Chaque smell dispose d'un `checkov_id` correspondant (ex. `CKV_AWS_20`, `CKV_K8S_16`). Les smells non couverts par Checkov (Ansible, Docker COPY) utilisent `HEURISTIC` et sont détectés par l'analyseur contextuel.

---

## 4. Architecture Technique Détaillée

### 4.1 Module 1 — Analyseur Contextuel (`analyzer/contextual.py`)

**Rôle :** Identifier l'outil IaC et localiser les smells.

**Approche en deux phases :**

- **Phase 1 (implémentée) :** Détection heuristique par regex + appel Checkov pour les smells détectables par outil statique. Rapide, pas de dépendance ML.
- **Phase 2 (à implémenter) :** Embeddings CodeBERT pour détecter les smells sémantiques que Checkov manque (ex. mauvais usage de variables secrètes, configuration indirecte).

**Métriques extraites :** nombre de lignes, tokens, lignes vides, commentaires — entrées pour le futur modèle de prédiction (Dalla Palma et al. [9] Random Forest).

### 4.2 Module 2 — Base de Connaissance (`knowledge/knowledge_base.py`)

**Rôle :** Stocker la taxonomie des 62 smells et des exemples de fixes sous forme de vecteurs.

**Choix technique :** ChromaDB (persistant, open-source) + `all-MiniLM-L6-v2` (sentence-transformers) pour les embeddings. Alternative possible : FAISS + OpenAI embeddings.

**Population de la base :**
1. Charger `dataset/taxonomy/smells_taxonomy.json` (à créer — voir §6.1)
2. Pour chaque entrée : `name + category + description + CWE + fix_example` → vecteur
3. Enrichir avec des rapports d'audit réels (GenSIAC dataset si accessible)

### 4.3 Module 3 — Récupérateur RAG (`knowledge/retriever.py`)

**Stratégie :** CRAG (Corrective RAG — Yao et al., 2024) avec adaptation au retry.

| Tentative | Stratégie de requête                                      |
|-----------|-----------------------------------------------------------|
| 1         | Query directe : `"iac_tool + smell_descriptions"`         |
| 2         | Ajout : `"Focus on minimal, targeted changes only"`       |
| 3+        | Ajout : `"Most conservative and safe remediation"`        |

Cela implémente la boucle d'auto-correction sans nécessiter un module CRAG complet dès la phase 1.

### 4.4 Module 4 — Générateur de Fix (`generator/fix_generator.py`)

**Rôle :** Appeler un LLM avec un prompt structuré pour produire un patch en format unified diff.

**Prompt engineering :**
- **System prompt :** rôle expert IaC security, contrainte de sortie diff uniquement
- **User prompt :** outil IaC + smells détectés + contexte RAG + script original
- **Température :** 0.2 (déterminisme maximal)
- **Confidence score :** filtrage des patches à faible confiance (< 0.6), inspiré de SecLLM

**Backend supporté :** OpenAI (GPT-4o-mini par défaut) ou Anthropic (Claude Sonnet) via variable d'environnement.

**Évolution future :** Fine-tuning sur dataset GenSIAC pour améliorer la précision sur les smells IaC spécifiques.

### 4.5 Module 5 — Validateur Externe (`validator/tool_integrator.py`)

**Rôle :** C'est le module **clé** qui distingue ce framework d'un RAG passif.

**Processus de validation :**
1. Appliquer le patch sur une copie temporaire du fichier (via `patch -u`)
2. Exécuter Checkov sur le fichier original → set `original_ids`
3. Exécuter Checkov sur le fichier patché → set `patched_ids`
4. Le patch est **valide** si :
   - Tous les `checker_id` des smells ciblés ont disparu
   - Aucun nouveau check_id n'est apparu (`patched_ids - original_ids = ∅`)

**Avantage :** La validation est **indépendante du LLM** — le framework ne fait confiance qu'aux outils statiques certifiés.

### 4.6 Module 6 — Formateur de Patch (`formatter/patch_formatter.py`)

Produit :
- Un **unified diff** propre (applicable avec `git apply` ou `patch -u`)
- Une **explication en langage naturel** avec références CWE pour chaque smell corrigé

---

## 5. Flux de Données Complet

```
Script IaC (input)
        │
        ▼
┌──────────────────┐
│ ContextualAnalyzer│  → détecte l'outil + lance Checkov
│  (Phase 1: regex) │  → retourne: {tool, smells[], metrics}
└──────────┬───────┘
           │ smells
           ▼
┌──────────────────┐
│ KnowledgeRetriever│  → query ChromaDB avec les smells
│   (RAG/CRAG)     │  → retourne: contexte textuel (top-5 docs)
└──────────┬───────┘
           │ rag_context
           ▼
┌──────────────────┐
│  FixGenerator    │  → prompt LLM avec script + smells + context
│  (OpenAI/Claude) │  → retourne: [patch_candidate_1, patch_candidate_2, ...]
└──────────┬───────┘
           │ patches[]
           ▼
┌──────────────────┐     ┌─────────────────┐
│ExternalValidator │────►│    Checkov       │
│  (tool_integrator)│     │ (avant vs après) │
└──────────┬───────┘     └─────────────────┘
           │
      ┌────┴────┐
      │ Valide? │
      └──┬───┬──┘
    OUI  │   │  NON (max 3 retry)
         │   └──► Refine RAG query → FixGenerator
         ▼
┌──────────────────┐
│  PatchFormatter  │  → unified diff + explication CWE
└──────────────────┘
         │
         ▼
Patch validé + Explication (output)
```

---

## 6. Plan d'Implémentation par Phase

### Phase 1 — Fondations (Semaines 1-2)

**Objectif :** Pipeline fonctionnel end-to-end avec Checkov + LLM, sans RAG.

- [ ] Installer l'environnement : `pip install -r requirements.txt`
- [ ] Tester le dataset : `bash scripts/run_checkov.sh`
- [ ] Implémenter `ContextualAnalyzer` (heuristiques + Checkov)
- [ ] Implémenter `FixGenerator` avec prompt de base (OpenAI ou Claude)
- [ ] Implémenter `ExternalToolValidator` (Checkov before/after)
- [ ] Implémenter `PatchFormatter`
- [ ] Câbler `CentralAgent` pour les fichiers Terraform
- [ ] Valider sur `dataset/terraform/insecure_s3.tf`

**Livrable Phase 1 :** Le système corrige au moins 1 smell Terraform et le valide avec Checkov.

### Phase 2 — Base de Connaissance RAG (Semaines 3-4)

**Objectif :** Intégrer ChromaDB et améliorer la qualité des patches via contexte.

- [ ] Créer `dataset/taxonomy/smells_taxonomy.json` (62 entrées)
- [ ] Peupler la base avec la taxonomie de War et al.
- [ ] Intégrer `KnowledgeBase` et `KnowledgeRetriever` dans le pipeline
- [ ] Comparer la qualité des patches avec/sans RAG sur le dataset complet
- [ ] Étendre à Ansible et Kubernetes

**Livrable Phase 2 :** RAG fonctionnel, métriques Precision/Recall calculées sur les 27 smells.

### Phase 3 — Boucle de Retry CRAG (Semaine 5)

**Objectif :** Implémenter la logique de retry avec requête RAG affinée.

- [ ] Activer le retry loop dans `CentralAgent` (max 3 tentatives)
- [ ] Implémenter `KnowledgeRetriever._build_query()` avec variation par retry
- [ ] Mesurer le taux de succès au 1er/2e/3e essai sur le dataset

**Livrable Phase 3 :** Comparaison taux de succès RAG passif vs CRAG actif.

### Phase 4 — Évaluation et Métriques (Semaine 6)

**Objectif :** Produire les résultats pour le mémoire.

- [ ] Implémenter le script d'évaluation automatique sur tout le dataset
- [ ] Calculer : Precision, Recall, F1-score, taux de validation Checkov
- [ ] Comparer : LLM seul vs LLM+RAG vs LLM+RAG+Validator (ablation study)
- [ ] Documenter les cas d'échec (smells non corrigés)

---

## 7. Métriques d'Évaluation

### 7.1 Métriques Principales

| Métrique           | Définition                                                              |
|--------------------|-------------------------------------------------------------------------|
| **Smell Detection Rate** | % de smells correctement identifiés par l'analyseur contextuel    |
| **Patch Success Rate**   | % de patches validés par Checkov au premier essai                 |
| **Fix Precision**        | % de patches qui suppriment le smell sans introduire de nouvelles erreurs |
| **Fix Recall**           | % de smells ciblés effectivement résolus                          |
| **F1-Score**             | Harmonic mean de Precision et Recall                              |
| **Retry Effectiveness**  | Gain de succès aux essais 2 et 3 vs essai 1                      |

### 7.2 Étude d'Ablation (Comparaisons)

```
Baseline 1 : LLM seul (pas de RAG, pas de validation externe)
Baseline 2 : LLM + RAG passif (pas de boucle de retry, pas de Checkov)
Notre système : LLM + RAG/CRAG + Validation Checkov + Retry
```

Ces trois configurations permettent de quantifier la contribution de chaque module.

### 7.3 Cibles de Performance (Estimées)

Basé sur la littérature (SecLLM F1=0.85, LLM vs Static Analyzer F1=0.75-0.80) :

| Configuration        | F1 Estimé |
|----------------------|-----------|
| Baseline LLM seul    | 0.40–0.55 |
| LLM + RAG passif     | 0.60–0.70 |
| Notre système complet| 0.75–0.85 |

---

## 8. Installation et Utilisation

### 8.1 Prérequis

```bash
# Python 3.10+
pip install -r requirements.txt

# Checkov (validateur IaC)
pip install checkov

# Clé API LLM (choisir un des deux)
export OPENAI_API_KEY="sk-..."
# OU
export ANTHROPIC_API_KEY="sk-ant-..."
```

### 8.2 Tester le Dataset

```bash
# Scanner tous les fichiers du dataset avec Checkov
bash scripts/run_checkov.sh

# Vérifier que les smells attendus sont bien détectés
pytest tests/test_validator.py -v
```

### 8.3 Lancer le Framework (Phase 1)

```python
from pathlib import Path
from src.analyzer.contextual import ContextualAnalyzer
from src.generator.fix_generator import FixGenerator
from src.validator.tool_integrator import ExternalToolValidator
from src.formatter.patch_formatter import PatchFormatter
from src.agent.orchestrator import CentralAgent

# Instancier les modules
agent = CentralAgent(
    analyzer=ContextualAnalyzer(),
    retriever=None,          # None en Phase 1 (pas de RAG encore)
    generator=FixGenerator(model="gpt-4o-mini"),
    validator=ExternalToolValidator(),
    formatter=PatchFormatter(),
)

# Analyser et corriger un fichier
result = agent.run("dataset/terraform/insecure_s3.tf")

if result["success"]:
    print(result["patch"])
    print(result["explanation"])
```

---

## 9. Choix Techniques Motivés

| Décision                          | Justification                                                                       |
|-----------------------------------|-------------------------------------------------------------------------------------|
| **ChromaDB** pour le vector store | Open-source, persistant, s'intègre directement avec sentence-transformers           |
| **all-MiniLM-L6-v2**             | Léger (80MB), efficace pour la recherche sémantique de code, sans coût API          |
| **Checkov** comme validateur      | Standard industriel, supporte Terraform + K8s + Ansible + Docker, sortie JSON stable |
| **Unified diff** pour les patches | Format standard utilisable directement avec `git apply` ou `patch -u`              |
| **Retry max 3**                   | Compromis coût API / taux de succès (au-delà de 3, le gain marginal est faible)    |
| **Temperature 0.2**               | Déterminisme pour les patches de sécurité (éviter la créativité non voulue)        |
| **Anthropic/OpenAI interchangeable** | Flexibilité pour tests et comparaisons (Claude vs GPT)                          |

---

## 10. Limitations et Perspectives

### Limitations du Dataset (v1.0)
- 27 smells sur 8 fichiers — trop petit pour une évaluation statistiquement robuste
- Smells créés manuellement — peut ne pas refléter la diversité des erreurs réelles
- Ansible et Docker pas couverts par Checkov → validation limitée aux heuristiques

### Évolutions Prioritaires
1. **Agrandir le dataset** : extraire des fichiers IaC réels depuis GitHub (dépôts publics) et les annoter avec Checkov
2. **Ajouter GLITCH** : pour couvrir les smells Ansible/Chef non détectés par Checkov
3. **Fine-tuning** : entraîner un modèle sur le dataset GenSIAC pour améliorer la précision des patches
4. **Interface utilisateur** : CLI interactive avec `typer` ou interface web minimaliste

---

*Ce rapport sera complété au fur et à mesure de l'avancement de l'implémentation.*
