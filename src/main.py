from data_preprocessing import load_data, clean_and_split, remove_constant_features

train_df, test_df = load_data('data/Training.parquet', 'data/Testing.parquet')
X_train, X_test, y_train, y_test = clean_and_split(train_df, test_df)
X_train, X_test, removed_cols = remove_constant_features(X_train, X_test)

print("Removed constant columns:", removed_cols)
print("Count:", len(removed_cols))
print("Final X_train shape:", X_train.shape)
print("Final X_test shape:", X_test.shape)