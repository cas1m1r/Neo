import joblib
from sklearn.metrics import accuracy_score, classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from tqdm import tqdm
import pandas as pd
import numpy as np
import pickle
import spacy
import sys

def pre_process_classes(cve_data):
    im_idx = []
    for rating in list(cve_data['vuln_class']):
        if rating == '?':
            im_idx.append(float(0.0))
        else:
            im_idx.append(float(rating))
    cve_data['vuln_class'] = np.array(im_idx)
    return cve_data


def pre_process_impacts(cve_data):
    im_idx = []
    for rating in list(cve_data['Impact']):
        if rating == '?':
            im_idx.append('0')
        else:
            im_idx.append(float(rating))
    cve_data['Impact'] = np.array(im_idx)
    return cve_data


def pre_process_vectors(cve_data):
    vectors = unique(list(cve_data['AttackVector']))
    d = dict(zip(vectors, list(range(len(vectors)))))
    cve_data['AttackVector'] = [d[row] for row in cve_data['AttackVector']]
    return cve_data


def pre_process_severity(cve_data):
    severities = unique(list(cve_data['Severity']))
    d = dict(zip(severities, list(range(len(severities)))))
    cve_data['Severity'] = [d[row] for row in cve_data['Severity']]
    return cve_data


def pre_process_complexity(cve_data):
    levels = unique(list(cve_data['complexity']))
    d = dict(zip(levels, list(range(len(levels)))))
    cve_data['complexity'] = [d[row] for row in cve_data['complexity']]
    return cve_data


def pre_process_privilege(cve_data):
    levels = unique(list(cve_data['requiredPrivilege']))
    d = dict(zip(levels, list(range(len(levels)))))
    cve_data['requiredPrivilege'] = [d[row] for row in cve_data['requiredPrivilege']]
    return cve_data


# use this utility function to get the preprocessed text data
def preprocess_text(column):
    # load english language model and create nlp object from it
    nlp = spacy.load("en_core_web_sm")
    data = list()
    for text in tqdm(column):
        # remove stop words and tokenize the text
        doc = nlp(text)
        filtered_tokens = []
        for token in doc:
            if token.is_stop or token.is_punct:
                continue
            filtered_tokens.append(token.lemma_)
        data.append(' '.join(filtered_tokens))
    return np.array(data)


def unique(l:list):
    result=[]
    for val in l:
        if val not in result:
            result.append(val)
    return result

def load_class_labels():
    classes = {}
    labels = [str(i) for i in range(19)]
    with open('class_labels.txt','r') as f:
        raw_data = f.read().splitlines()
    for ln in raw_data:
        fields = ln.split(':')
        if fields[0] in labels:
            classes[int(fields[0])] = fields[-1]

    return classes

def train_random_tree_classifier(df):
    features = ['details', 'vuln_class']

    df = df[features]
    df = pre_process_classes(df)
    # Preprocess
    # TODO: Preprocess text in details for NLP
    # Print the shape of dataframe
    print(df.shape)

    # Print top 5 rows
    df.head(5)
    df.dropna(inplace=True)

    print('[-] Pre Processing Text')
    # df['Preprocessed Text'] = preprocess_text(df['details'])
    le_model = LabelEncoder()
    df['vuln_class'] = le_model.fit_transform(df['vuln_class'])
    print('[-] Creating test and training sets')
    X_train, X_test, y_train, y_test = train_test_split(df['details'], df['vuln_class'],
                                                        test_size=0.2, random_state=42, stratify=df['vuln_class'])
    print("X_train: \t", X_train.shape)
    print("X_test: \t", X_test.shape)
    # # Create classifier
    # clf = Pipeline([
    #     ('vectorizer_tri_grams', TfidfVectorizer()),
    #     ('naive_bayes', (MultinomialNB()))
    # ])
    # print(f'[-] Training Classifier')
    # # Model training
    # clf.fit(X_train, y_train)
    #
    # # Get prediction
    # y_pred = clf.predict(X_test)
    #
    # # Print score
    # print(accuracy_score(y_test, y_pred))
    #
    # # Print classification report
    # print(classification_report(y_test, y_pred))
    #
    # joblib.dump(clf, 'classifier.pkl', compress=1)
    print('[+] Training random forest now')

    clf = Pipeline([
        ('vectorizer_tri_grams', TfidfVectorizer()),
        ('naive_bayes', (RandomForestClassifier()))
    ])
    clf.fit(X_train, y_train)
    # Get the predictions for X_test and store it in y_pred
    y_pred = clf.predict(X_test)
    # Print Accuracy
    print(accuracy_score(y_test, y_pred))
    # Print the classfication report
    print(classification_report(y_test, y_pred))
    joblib.dump(clf, 'random_forest.pkl', compress=1)
    with open(f'random_forest_2.pkl','wb') as f:
        pickle.dump(clf, f)
    return clf


def model_prediction(model, text_to_evaluate):
    prediction = model.predict(preprocess_text([text_to_evaluate]))
    probabilities = model.predict_proba(preprocess_text([text_to_evaluate]))
    labels = load_class_labels()
    if len(prediction):
        print(f'[+] Predicted Class: {prediction} [{labels[prediction[0]]}]')
    print(f'[+] Prediction Probabilities:\n')
    for i in range(1,len(labels.keys())):
        pct = probabilities[0, i] * 100
        print(f'  {pct}% {labels[i]}')
    return prediction, probabilities

def load_model(fname):
    with open(fname, 'rb') as f:
        model = pickle.load(f, encoding='bytes')
    f.close()
    return model


if __name__ == '__main__':

    if 'train' in sys.argv:
        cve_data = "cve_data.csv"
        df = pd.read_csv(cve_data)
        rtee_clf = train_random_tree_classifier(df)

    if 'evaluate' in sys.argv:
        text_to_evaluate = ' '.join(sys.argv[2:])
        print(f'[+] Evalauting RandomTreeClassifier on description: \n{text_to_evaluate}')
        model = load_model('random_forest_2.pkl')
        print(f'[+] Model Loaded')

        # make a prediction
        model_prediction(model, text_to_evaluate)