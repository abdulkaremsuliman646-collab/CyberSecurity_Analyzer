import pandas as pd
train_df = pd.read_parquet('data/Training.parquet')
test_df = pd.read_parquet('data/Testing.parquet')

train_df['status'] = train_df['status'].map({'legitimate':0, 'phishing':1})
test_df['status'] = test_df['status'].map({'legitimate':0, 'phishing':1})
X_train = train_df.drop(columns=['url', 'status'])
X_test = test_df.drop(columns=['url', 'status'])
y_train = train_df['status']
y_test = test_df['status']
print("X_train shape:", X_train.shape)
print("X_test shape:", X_test.shape)
print("y_train shape:", y_train.shape)
print("y_test shape:", y_test.shape)
print("\n--- Encoding Check ---")
print("y_train:\n", y_train.value_counts(dropna=False))
print("y_test:\n", y_test.value_counts(dropna=False))
correlation = X_train.corrwith(y_train).sort_values(ascending=False)
print("\n--- top 10 phishing indicators (Positive correlation) ---") 
print(correlation.head(10))
print("\n--- top 10 phishing indicators (Negative correlation) ---") 
print(correlation.tail(10)) 