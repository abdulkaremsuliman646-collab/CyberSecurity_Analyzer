import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)
from data_preprocessing import load_data, clean_and_split, remove_constant_features

def prepare_dataset():
    train_df, test_df = load_data('data/Training.parquet', 'data/Testing.parquet')
    X_train, X_test, y_train, y_test = clean_and_split(train_df, test_df)
    X_train, X_test, _ = remove_constant_features(X_train, X_test)
    return X_train, X_test, y_train, y_test

def train_random_forest(X_train, y_train):
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    return model

def evaluate_model(model, X_test, y_test):
    y_pred = model.predict(X_test)
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall': recall_score(y_test, y_pred),
        'f1_score': f1_score(y_test, y_pred),
        'confusion_matrix': confusion_matrix(y_test, y_pred)
    }
    return metrics

def get_top_features(model, feature_names, top_n=10):
    importances = pd.Series(model.feature_importances_, index=feature_names)
    return importances.sort_values(ascending=False).head(top_n)

def save_model(model, filepath='models/phishing_rf_model.joblib'):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    joblib.dump(model, filepath, compress=3)
    return filepath

if __name__ == "__main__":
    print("1. Loading and cleaning dataset...")
    X_train, X_test, y_train, y_test = prepare_dataset()
    print(f"   Training samples: {X_train.shape[0]} | Features: {X_train.shape[1]}")

    print("\n2. Training Random Forest AI model...")
    model = train_random_forest(X_train, y_train)
    print("   Training completed successfully!")

    print("\n3. Evaluating model on unseen test URLs...")
    results = evaluate_model(model, X_test, y_test)
    cm = results['confusion_matrix']

    print(f"   Accuracy  : {results['accuracy'] * 100:.2f}%")
    print(f"   Precision : {results['precision'] * 100:.2f}%")
    print(f"   Recall    : {results['recall'] * 100:.2f}%")
    print(f"   F1-Score  : {results['f1_score'] * 100:.2f}%")

    print("\n   Confusion Matrix:")
    print(f"   - Safe predicted Safe (TN)        : {cm[0][0]}")
    print(f"   - Safe predicted Phishing (FP)    : {cm[0][1]}")
    print(f"   - Phishing predicted Safe (FN)    : {cm[1][0]}")
    print(f"   - Phishing predicted Phishing (TP): {cm[1][1]}")

    print("\n4. Top 10 Most Important Security Features:")
    top_features = get_top_features(model, X_train.columns, top_n=10)
    for rank, (name, score) in enumerate(top_features.items(), start=1):
        print(f"   {rank}. {name}: {score * 100:.2f}%")

    saved_path = save_model(model)
    print(f"\n5. Model saved successfully to: {saved_path}")