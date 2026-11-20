import pandas as pd

def load_data(train_path, test_path):
    train_df = pd.read_parquet(train_path)
    test_df = pd.read_parquet(test_path)
    return train_df, test_df

def clean_and_split(train_df, test_df):
    train_df['status'] = train_df['status'].map({'legitimate': 0, 'phishing': 1})
    test_df['status'] = test_df['status'].map({'legitimate': 0, 'phishing': 1})

    X_train = train_df.drop(columns=['url', 'status'])
    X_test = test_df.drop(columns=['url', 'status'])
    y_train = train_df['status']
    y_test = test_df['status']

    return X_train, X_test, y_train, y_test

def remove_constant_features(X_train, X_test):
    constant_cols = []
    for col in X_train.columns:
        if X_train[col].nunique() <= 1:
            constant_cols.append(col)

    X_train = X_train.drop(columns=constant_cols)
    X_test = X_test.drop(columns=constant_cols)

    return X_train, X_test, constant_cols