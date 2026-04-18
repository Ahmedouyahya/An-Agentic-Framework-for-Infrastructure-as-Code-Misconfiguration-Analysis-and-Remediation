# Training

Fine-tuning the IaC security fix model.

```
training/
├── data/         Filtered dataset for Kaggle upload (created by 01_prepare_dataset.py)
└── trainning/    Python scripts to run locally (prep) and on Kaggle (train/infer)
```

See `trainning/README.md` for the full recipe.

## Quick start

```bash
# 1. Filter v1 dataset locally (reads ../scraping/output/dataset_v1_validated.jsonl)
python training/trainning/01_prepare_dataset.py

# 2. Upload training/data/ as a Kaggle dataset, then run 02_train_qlora.py in
#    a Kaggle notebook (GPU T4 x2).
```

The ~322 MB raw dataset is NOT copied here — it lives in `scraping/output/`
and the prep script pulls only the scanner-validated subset (~10k records,
a few MB).

The full dataset is published separately at
**https://github.com/Ahmedouyahya/iac-security-dataset** — download
`dataset.jsonl` from there into `Code/scraping/output/dataset_v1_validated.jsonl`
before running `01_prepare_dataset.py`.
