from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from ml_model import prepare_dataset, evaluate_model
from sklearn.metrics import precision_score, recall_score, confusion_matrix


def get_models():
    return {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "Logistic Regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=1000, random_state=42)
        ),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42),
    }


def compare_models(models, X_train, X_test, y_train, y_test):
    for name, model in models.items():
        model.fit(X_train, y_train)
        print(f"\n--- Training {name} ---")
        results = evaluate_model(model, X_test, y_test)
        fn = results["confusion_matrix"][1][0]

        print(f"Accuracy : {results['accuracy'] * 100:.2f}%")
        print(f"Recall   : {results['recall'] * 100:.2f}%")
        print(f"F1-Score : {results['f1_score'] * 100:.2f}%")
        print(f"Missed Phishing (FN): {fn}")


def optimize_threshold(model, X_test, y_test):
    probs = model.predict_proba(X_test)[:, 1]
    thresholds = [0.50, 0.40, 0.35, 0.30]
    print("\n--- Threshold Optimization ---")
    for threshold in thresholds:
        custom_preds = (probs >= threshold).astype(int)
        cm = confusion_matrix(y_test, custom_preds)
        fp = cm[0][1]
        fn = cm[1][0]
        rec = recall_score(y_test, custom_preds, zero_division=0)
        prec = precision_score(y_test, custom_preds, zero_division=0)
        print(
            f"Threshold {threshold:.2f} | Recall: {rec * 100:.2f}% | "
            f"Precision: {prec * 100:.2f}% | Missed (FN): {fn} | False Alarms (FP): {fp}"
        )


if __name__ == "__main__":
    X_train, X_test, y_train, y_test = prepare_dataset()
    models = get_models()
    compare_models(models, X_train, X_test, y_train, y_test)
    best_model = models["Random Forest"]
    optimize_threshold(best_model, X_test, y_test)