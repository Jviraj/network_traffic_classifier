from sklearn.decomposition import PCA
# Specify the CSV file path
csv_file_path = 'output_ndpi_training_testing.csv'

# Import necessary libraries
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Load the dataset
dataset = pd.read_csv(csv_file_path)

# Separate features and target
X = dataset.drop('Category', axis = 1)
y = dataset['Category']

# Split the dataset into an 90-10 training-test set
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.1, random_state = 42)

# Create an instance of the StandardScaler class
from sklearn.preprocessing import StandardScaler
sc = StandardScaler()
weights = np.array([[0.2, 0, 0, 0, 0], [0, 0.3, 0, 0, 0], [0, 0, 0.2, 0, 0], [0, 0, 0, 0.2, 0], [0, 0, 0, 0, 0.1]])
# Fit the StandardScaler on the features from the training set and transform it
X_train = sc.fit_transform(X_train)
X_train = np.dot(X_train, weights)
# Apply the transform to the test set
X_test = sc.transform(X_test)
X_test = np.dot(X_test, weights)
# Print the scaled training and test datasets
# print(X_train)
# print(X_test)

#K-NN
from sklearn.neighbors import KNeighborsClassifier
classifier = KNeighborsClassifier(n_neighbors=2, metric='minkowski', p=1)
classifier.fit(X_train, y_train)
#SVM
# from sklearn.svm import SVC
# classifier = SVC(kernel = 'linear', random_state = 0)
# classifier.fit(X_train, y_train)

#Predict the results
y_pred = classifier.predict(X_test)
from sklearn.metrics import accuracy_score
print(accuracy_score(y_test, y_pred))

csv_file_path2 = 'output_ndpi_predicting.csv'
dataset2 = pd.read_csv(csv_file_path2)

# pca = PCA(n_components=2)
# X_train_pca = pca.fit_transform(X_train)
# X_test_pca = pca.transform(X_test)

# # Create the scatter plot for the test data points with predicted categories
# categories = np.unique(y_test)
# colors = ['r', 'g', 'b', 'y', 'm', 'c']  # You may need to extend the colors list for more categories
# plt.figure(figsize=(8, 6))

# for category, color in zip(categories, colors):
#     mask = y_pred == category
#     plt.scatter(X_test_pca[mask, 0], X_test_pca[mask, 1], c=color, label=f'Category {category}', alpha=0.7)

# plt.xlabel('Principal Component 1')
# plt.ylabel('Principal Component 2')
# plt.title('KNN Algorithm - Scatter Plot with PCA')
# plt.legend()
# plt.show()

# Separate features and target
X2 = dataset2.drop('Category', axis = 1)
print(X2[1])
y2 = dataset2['Category']
X3 = sc.fit_transform(X2)
X2 = np.dot(X2, weights)
y_pred2 = classifier.predict(X3)
print(accuracy_score(y2, y_pred2))