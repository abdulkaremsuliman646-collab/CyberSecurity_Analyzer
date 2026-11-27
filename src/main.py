from data_preprocessing import load_data, clean_and_split, remove_constant_features
from risk_analyzer import analyze_url_full
from ml_model import (
    prepare_dataset,
    train_random_forest,
    evaluate_model,
    get_top_features,
    save_model
)

from report_generator import scan_urls_from_file, save_json_report, save_csv_report

def run_preprocessing_pipeline():
    print("\n--- Running Dataset Preprocessing Pipeline ---")
    train_df, test_df = load_data('data/Training.parquet', 'data/Testing.parquet')
    X_train, X_test, y_train, y_test = clean_and_split(train_df, test_df)
    X_train, X_test, removed_cols = remove_constant_features(X_train, X_test)

    print("Removed constant columns:", removed_cols)
    print("Count:", len(removed_cols))
    print("Final X_train shape:", X_train.shape)
    print("Final X_test shape:", X_test.shape)

def run_live_url_scanner():
    url = input("\nEnter a URL to analyze (e.g. google.com): ")
    result = analyze_url_full(url)
    risk = result['risk_assessment']
    ssl_info = result['ssl_report']

    print("\n" + "=" * 50)
    print("URL:", result['url'])
    print("Hostname:", result['url_features']['hostname'])
    print("SSL Valid:", ssl_info['valid_ssl'])
    if ssl_info['valid_ssl']:
        print("SSL Issuer:", ssl_info['issuer'], "| Days Left:", ssl_info['days_left'])
    print("Risk Score:", risk['score'], "/ 100")
    print("Verdict:", risk['risk_level'])

    if risk['reasons']:
        print("Detected Threats:")
        for reason in risk['reasons']:
            print("  -", reason)
    else:
        print("Detected Threats: None")
    print("=" * 50)

def run_ml_training_pipeline():
    print("\n--- Training & Evaluating Phishing Detection AI Model ---")
    X_train, X_test, y_train, y_test = prepare_dataset()
    model = train_random_forest(X_train, y_train)
    results = evaluate_model(model, X_test, y_test)
    saved_path = save_model(model)

    print(f"Accuracy  : {results['accuracy'] * 100:.2f}%")
    print(f"Precision : {results['precision'] * 100:.2f}%")
    print(f"Recall    : {results['recall'] * 100:.2f}%")
    print(f"F1-Score  : {results['f1_score'] * 100:.2f}%")

    print("\nTop 5 Most Important Features:")
    top_features = get_top_features(model, X_train.columns, top_n=5)
    for rank, (name, score) in enumerate(top_features.items(), start=1):
        print(f"  {rank}. {name}: {score * 100:.2f}%")

    print(f"\nModel saved to: {saved_path}")


def run_batch_scanner():
    filepath = input("\nEnter path to URLs file (default: urls.txt): ").strip()
    if not filepath:
        filepath = "urls.txt"

    try:
        results = scan_urls_from_file(filepath)
        if not results:
            print("The file is empty. No URLs to scan.")
            return

        json_path = save_json_report(results)
        csv_path = save_csv_report(results)
        print(f"\nBatch scan completed! Scanned {len(results)} URLs.")
        print(f"JSON Report saved to: {json_path}")
        print(f"CSV Report saved to : {csv_path}")
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found. Please check the file name.")

if __name__ == "__main__":
    while True:
        print("\n=== CyberSecurity Analyzer Menu ===")
        print("1. Run Dataset Preprocessing Pipeline")
        print("2. Scan a Live URL (SSL + URL Features + Risk Score)")
        print("3. Train, Evaluate & Save ML Model (Random Forest)")
        print("4. Batch Scan URLs from File (Export JSON & CSV)")
        print("5. Exit")

        choice = input("Select an option (1/2/3/4/5): ").strip()
        if choice == "1":
            run_preprocessing_pipeline()
        elif choice == "2":
            run_live_url_scanner()
        elif choice == "3":
            run_ml_training_pipeline()
        elif choice == "4":
            run_batch_scanner()
        elif choice == "5":
            print("Exiting CyberSecurity Analyzer. Stay safe!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, 4, or 5.")
