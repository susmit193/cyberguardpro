import argparse
import os
import pickle
import sys
from dataclasses import dataclass
from typing import List, Dict, Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, roc_auc_score

# Allow importing URLAnalyzer from ML/
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)
from url_analyzer import URLAnalyzer  # noqa: E402


@dataclass
class TrainConfig:
    data_path: str
    output_path: str
    calibrate: bool = True
    test_size: float = 0.2
    random_state: int = 42
    max_features_tfidf: int = 300


def extract_tabular_features(urls: List[str], analyzer: URLAnalyzer) -> pd.DataFrame:
    feature_rows: List[Dict[str, Any]] = []
    for url in urls:
        try:
            feats = analyzer.extract_features(url)
        except Exception:
            feats = {}
        feats['__url__'] = url
        feature_rows.append(feats)
    return pd.DataFrame(feature_rows)


def build_feature_matrix(df_feats: pd.DataFrame, tfidf: TfidfVectorizer) -> np.ndarray:
    # Separate URL column for TF-IDF
    urls = df_feats['__url__'].fillna("").astype(str).tolist()
    tfidf_mat = tfidf.transform(urls).toarray()

    # Numeric features: drop the helper URL column
    numeric_df = df_feats.drop(columns=['__url__'])
    # Fill missing with zeros
    numeric_df = numeric_df.fillna(0)
    X_num = numeric_df.values.astype(float)

    # Concatenate numeric + tfidf
    return np.hstack([X_num, tfidf_mat])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', dest='data_path', required=True, help='Path to CSV with columns: url,label')
    parser.add_argument('--output', dest='output_path', default=os.path.join(CURRENT_DIR, 'malware_model.pkl'))
    parser.add_argument('--no-calibrate', dest='calibrate', action='store_false', help='Disable probability calibration')
    parser.add_argument('--test-size', type=float, default=0.2)
    parser.add_argument('--random-state', type=int, default=42)
    parser.add_argument('--tfidf-max', type=int, default=300)
    args = parser.parse_args()

    cfg = TrainConfig(
        data_path=args.data_path,
        output_path=args.output_path,
        calibrate=args.calibrate,
        test_size=args.test_size,
        random_state=args.random_state,
        max_features_tfidf=args.tfidf_max,
    )

    print('Loading dataset…')
    data = pd.read_csv(cfg.data_path)
    if 'url' not in data.columns or 'label' not in data.columns:
        raise ValueError('CSV must include columns: url,label')

    data = data.dropna(subset=['url', 'label']).copy()
    data['url'] = data['url'].astype(str)
    data['label'] = data['label'].astype(int)

    X_train_urls, X_test_urls, y_train, y_test = train_test_split(
        data['url'].values, data['label'].values,
        test_size=cfg.test_size, random_state=cfg.random_state, stratify=data['label'].values
    )

    analyzer = URLAnalyzer(model_path='malware_model.pkl')  # model not used; just for feature extraction
    analyzer.model = None
    analyzer.vectorizer = None

    print('Extracting tabular features…')
    df_train_feats = extract_tabular_features(list(X_train_urls), analyzer)
    df_test_feats = extract_tabular_features(list(X_test_urls), analyzer)

    print('Fitting TF-IDF on URLs…')
    tfidf = TfidfVectorizer(ngram_range=(1, 3), analyzer='char', min_df=2, max_features=cfg.max_features_tfidf)
    tfidf.fit(list(X_train_urls))

    print('Building feature matrices…')
    X_train = build_feature_matrix(df_train_feats, tfidf)
    X_test = build_feature_matrix(df_test_feats, tfidf)

    print('Training classifier…')
    base_clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight='balanced',
        random_state=cfg.random_state,
        n_jobs=-1,
    )

    if cfg.calibrate:
        clf = CalibratedClassifierCV(base_estimator=base_clf, method='sigmoid', cv=3)
    else:
        clf = base_clf

    clf.fit(X_train, y_train)

    print('Evaluating…')
    y_pred = clf.predict(X_test)
    if hasattr(clf, 'predict_proba'):
        y_proba = clf.predict_proba(X_test)[:, 1]
        try:
            auc = roc_auc_score(y_test, y_proba)
            print(f'ROC AUC: {auc:.4f}')
        except Exception:
            pass
    print(classification_report(y_test, y_pred, digits=4))

    print(f'Saving model to {cfg.output_path} …')
    model_payload = {
        'model': clf,
        'vectorizer': tfidf,
    }
    with open(cfg.output_path, 'wb') as f:
        pickle.dump(model_payload, f)

    print('Done.')


if __name__ == '__main__':
    main()
