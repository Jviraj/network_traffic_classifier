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

#logistic regression
def logisticRegression():
    from sklearn.linear_model import LogisticRegression
    classifierLG = LogisticRegression(random_state = 0)
    classifierLG.fit(X_train, y_train)
    y_pred = classifierLG.predict(X_test)
    from sklearn.metrics import accuracy_score
    yt =[]
    yp = []
    j = -1
    for i in y_test:
        j += 1
        if i=="Network":
            continue
        yt.append(i)
        yp.append(y_pred[j])
    print(accuracy_score(yt, yp))

#K-NN
def KNearestNeighbours():
    from sklearn.neighbors import KNeighborsClassifier
    classifierKNN = KNeighborsClassifier(n_neighbors=2, metric='minkowski', p=1)
    classifierKNN.fit(X_train, y_train)
    y_pred = classifierKNN.predict(X_test)
    from sklearn.metrics import accuracy_score
    yt =[]
    yp = []
    j = -1
    for i in y_test:
        j += 1
        if i=="Network":
            continue
        yt.append(i)
        yp.append(y_pred[j])
    
    print(accuracy_score(yt, yp))

#SVM
def SVM():
    from sklearn.svm import SVC
    classifierSVM = SVC(kernel = 'linear', random_state = 0)
    classifierSVM.fit(X_train, y_train)
    y_pred = classifierSVM.predict(X_test)
    from sklearn.metrics import accuracy_score
    yt = []
    yp = []
    j = -1
    for i in y_test:
        j += 1
        if i=="Network":
            continue
        yt.append(i)
        yp.append(y_pred[j])

    print(accuracy_score(yt, yp))

#Kernel SVM
def KernelSVM():
    from sklearn.svm import SVC
    classifierKSVM = SVC(kernel = 'rbf', random_state = 0)
    classifierKSVM.fit(X_train, y_train)
    y_pred = classifierKSVM.predict(X_test)
    from sklearn.metrics import accuracy_score
    yt = []
    yp = []
    j = -1
    for i in y_test:
        j += 1
        if i=="Network":
            continue
        yt.append(i)
        yp.append(y_pred[j])

    print(accuracy_score(yt, yp))

#Naive Baeyes
def NaiveBaeyes():
    from sklearn.naive_bayes import GaussianNB
    classifierNB = GaussianNB()
    classifierNB.fit(X_train, y_train)
    y_pred = classifierNB.predict(X_test)
    from sklearn.metrics import accuracy_score
    yt = []
    yp = []
    j = -1
    for i in y_test:
        j += 1
        if i=="Network":
            continue
        yt.append(i)
        yp.append(y_pred[j])

    print(accuracy_score(yt, yp))

#Decision Tree
def DecisionTree():
    from sklearn.tree import DecisionTreeClassifier
    classifierDT = DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
    classifierDT.fit(X_train, y_train)
    y_pred = classifierDT.predict(X_test)
    from sklearn.metrics import accuracy_score
    yt = []
    yp = []
    j = -1
    for i in y_test:
        j += 1
        if i=="Network":
            continue
        yt.append(i)
        yp.append(y_pred[j])
    
    print(accuracy_score(yt, yp))

#Random Forest Classifier
def RandomForestClassifier():
    from sklearn.ensemble import RandomForestClassifier
    classifierRF = RandomForestClassifier(n_estimators = 100, criterion = 'entropy', random_state = 0)
    classifierRF.fit(X_train, y_train)
    y_pred = classifierRF.predict(X_test)
    from sklearn.metrics import accuracy_score
    yt = []
    yp = []
    j = -1
    for i in y_test:
        j += 1
        if i=="Network":
            continue
        yt.append(i)
        yp.append(y_pred[j])
    
    print(accuracy_score(yt, yp))